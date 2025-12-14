"""
WordPress Backup Tool Storage Manager

Handles local backup file management, archiving, verification, and retention.
"""

import tarfile
import hashlib
import json
import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional
import re

class BackupStorageError(Exception):
    """Backup storage related errors."""
    pass

class BackupVerifier:
    """Full verification of backup archives with checksums."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def verify_database_archive(self, archive_path: str) -> Dict:
        """Verify database archive integrity and content.
        
        Args:
            archive_path: Path to the database archive file
            
        Returns:
            Dictionary with verification results
        """
        result = {
            "archive_valid": False,
            "sql_valid": False,
            "checksum": None,
            "errors": []
        }
        
        try:
            # 1. Verify tar.gz archive integrity
            with tarfile.open(archive_path, 'r:gz') as tar:
                members = tar.getmembers()
                if not members:
                    result["errors"].append("Archive is empty")
                    return result
            result["archive_valid"] = True
            
            # 2. Extract and validate SQL content
            with tarfile.open(archive_path, 'r:gz') as tar:
                sql_member = members[0]  # Should be the SQL file
                sql_file = tar.extractfile(sql_member)
                if sql_file:
                    sql_content = sql_file.read().decode('utf-8', errors='replace')
                    
                    if self._validate_sql_syntax(sql_content):
                        result["sql_valid"] = True
                    else:
                        result["errors"].append("Invalid SQL syntax or content")
                else:
                    result["errors"].append("Could not extract SQL file from archive")
            
            # 3. Generate SHA256 checksum
            result["checksum"] = self._calculate_file_checksum(archive_path)
            
        except Exception as e:
            result["errors"].append(f"Archive verification failed: {str(e)}")
        
        return result
    
    def verify_files_archive(self, archive_path: str, expected_file_count: Optional[int] = None) -> Dict:
        """Verify files archive integrity and content.
        
        Args:
            archive_path: Path to the files archive
            expected_file_count: Expected number of files (optional)
            
        Returns:
            Dictionary with verification results
        """
        result = {
            "archive_valid": False,
            "file_count": 0,
            "checksum": None,
            "errors": []
        }
        
        try:
            # 1. Verify tar.gz archive integrity
            with tarfile.open(archive_path, 'r:gz') as tar:
                members = tar.getmembers()
                result["file_count"] = len([m for m in members if m.isfile()])
            result["archive_valid"] = True
            
            # 2. Validate file count if expected count provided
            if expected_file_count and result["file_count"] < expected_file_count * 0.95:
                result["errors"].append(f"File count too low: {result['file_count']} < {expected_file_count * 0.95}")
            
            # 3. Generate SHA256 checksum
            result["checksum"] = self._calculate_file_checksum(archive_path)
            
        except Exception as e:
            result["errors"].append(f"Archive verification failed: {str(e)}")
        
        return result
    
    def _validate_sql_syntax(self, sql_content: str) -> bool:
        """Basic SQL syntax validation for MySQL dumps.
        
        Args:
            sql_content: SQL file content
            
        Returns:
            True if SQL appears valid, False otherwise
        """
        # Check for minimum size
        if len(sql_content) < 100:
            return False
        
        # Required patterns for valid MySQL dump
        required_patterns = [
            r"-- MySQL dump",
            r"CREATE TABLE",
            r"INSERT INTO"
        ]
        
        for pattern in required_patterns:
            if not re.search(pattern, sql_content, re.IGNORECASE):
                self.logger.warning(f"Missing required pattern: {pattern}")
                return False
        
        # Check for common corruption/error signs
        corruption_signs = [
            r"ERROR \d+",
            r"Access denied",
            r"Connection failed",
            r"mysqldump: Error:",
            r"Unknown table"
        ]
        
        for sign in corruption_signs:
            if re.search(sign, sql_content, re.IGNORECASE):
                self.logger.error(f"Found corruption sign: {sign}")
                return False
        
        return True
    
    def _calculate_file_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file.
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA256 checksum as hex string
        """
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        
        return hash_sha256.hexdigest()
    
    def save_checksums(self, backup_dir: str, site_name: str, timestamp: str, 
                      db_checksum: str, files_checksum: str):
        """Save checksums to verification file.
        
        Args:
            backup_dir: Base backup directory
            site_name: Site name
            timestamp: Backup timestamp
            db_checksum: Database archive checksum
            files_checksum: Files archive checksum
        """
        site_backup_dir = Path(backup_dir) / site_name
        site_backup_dir.mkdir(parents=True, exist_ok=True)
        
        checksum_file = site_backup_dir / f"{site_name}_checksums.json"
        
        # Load existing checksums
        checksums = {}
        if checksum_file.exists():
            try:
                with open(checksum_file, 'r') as f:
                    checksums = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.logger.warning(f"Could not load existing checksums from {checksum_file}")
        
        # Add new checksums
        checksums[timestamp] = {
            "database": db_checksum,
            "files": files_checksum,
            "verified_at": datetime.now().isoformat()
        }
        
        # Save updated checksums
        try:
            with open(checksum_file, 'w') as f:
                json.dump(checksums, f, indent=2, sort_keys=True)
        except IOError as e:
            self.logger.error(f"Failed to save checksums: {e}")

class BackupStorage:
    """Local backup file management and archiving."""
    
    def __init__(self, backup_dir: str):
        """Initialize backup storage.
        
        Args:
            backup_dir: Base directory for storing backups
        """
        self.backup_dir = Path(backup_dir).resolve()
        self.logger = logging.getLogger(__name__)
        self.verifier = BackupVerifier(self.logger)
        
        # Create backup directory if it doesn't exist
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def create_db_archive(self, site_name: str, dump_file: str, timestamp: Optional[str] = None) -> str:
        """Create timestamped database archive.
        
        Args:
            site_name: Name of the WordPress site
            dump_file: Path to the SQL dump file
            timestamp: Optional timestamp (generates if not provided)
            
        Returns:
            Path to created archive file
            
        Raises:
            BackupStorageError: If archive creation fails
        """
        if timestamp is None:
            timestamp = self.generate_timestamp()
        
        # Create site-specific backup directory
        site_backup_dir = self.backup_dir / site_name
        site_backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate archive filename
        archive_name = f"{site_name}_db_{timestamp}.tar.gz"
        archive_path = site_backup_dir / archive_name
        
        try:
            self.logger.info(f"Creating database archive: {archive_name}")
            
            # Create tar.gz archive
            with tarfile.open(archive_path, 'w:gz') as tar:
                # Add SQL dump file with a clean name inside archive
                sql_name = f"{site_name}_db_{timestamp}.sql"
                tar.add(dump_file, arcname=sql_name)
            
            # Verify archive was created successfully
            if not archive_path.exists() or archive_path.stat().st_size == 0:
                raise BackupStorageError(f"Archive creation failed: {archive_path}")
            
            self.logger.info(f"Database archive created: {archive_path} ({archive_path.stat().st_size} bytes)")
            return str(archive_path)
            
        except Exception as e:
            # Cleanup incomplete archive
            if archive_path.exists():
                try:
                    archive_path.unlink()
                except Exception:
                    pass
            raise BackupStorageError(f"Failed to create database archive: {e}")
    
    def create_files_archive(self, site_name: str, files_dir: str, timestamp: Optional[str] = None) -> str:
        """Create timestamped files archive.
        
        Args:
            site_name: Name of the WordPress site
            files_dir: Directory containing synced files
            timestamp: Optional timestamp (generates if not provided)
            
        Returns:
            Path to created archive file
            
        Raises:
            BackupStorageError: If archive creation fails
        """
        if timestamp is None:
            timestamp = self.generate_timestamp()
        
        # Create site-specific backup directory
        site_backup_dir = self.backup_dir / site_name
        site_backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate archive filename
        archive_name = f"{site_name}_files_{timestamp}.tar.gz"
        archive_path = site_backup_dir / archive_name
        
        try:
            self.logger.info(f"Creating files archive: {archive_name}")
            
            files_path = Path(files_dir)
            if not files_path.exists():
                raise BackupStorageError(f"Files directory does not exist: {files_dir}")
            
            # Create tar.gz archive
            with tarfile.open(archive_path, 'w:gz') as tar:
                # Add all files from the directory
                for root, dirs, files in os.walk(files_dir):
                    for file in files:
                        file_path = Path(root) / file
                        # Calculate relative path for archive
                        rel_path = file_path.relative_to(files_path)
                        tar.add(file_path, arcname=str(rel_path))
            
            # Verify archive was created successfully
            if not archive_path.exists() or archive_path.stat().st_size == 0:
                raise BackupStorageError(f"Archive creation failed: {archive_path}")
            
            self.logger.info(f"Files archive created: {archive_path} ({archive_path.stat().st_size} bytes)")
            return str(archive_path)
            
        except Exception as e:
            # Cleanup incomplete archive
            if archive_path.exists():
                try:
                    archive_path.unlink()
                except Exception:
                    pass
            raise BackupStorageError(f"Failed to create files archive: {e}")
    
    def generate_timestamp(self) -> str:
        """Generate YYYY-MM-DD_HH-MM-SS timestamp.
        
        Returns:
            Timestamp string in specified format
        """
        return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    def verify_archive_integrity(self, archive_path: str, archive_type: str = "auto") -> bool:
        """Verify archive integrity and generate checksums.
        
        Args:
            archive_path: Path to archive file
            archive_type: Type of archive ("database", "files", or "auto")
            
        Returns:
            True if verification successful, False otherwise
        """
        try:
            # Auto-detect archive type from filename
            if archive_type == "auto":
                if "_db_" in Path(archive_path).name:
                    archive_type = "database"
                elif "_files_" in Path(archive_path).name:
                    archive_type = "files"
                else:
                    self.logger.error(f"Cannot determine archive type from filename: {archive_path}")
                    return False
            
            # Verify based on type
            if archive_type == "database":
                result = self.verifier.verify_database_archive(archive_path)
                success = result["archive_valid"] and result["sql_valid"]
            elif archive_type == "files":
                result = self.verifier.verify_files_archive(archive_path)
                success = result["archive_valid"]
            else:
                self.logger.error(f"Unknown archive type: {archive_type}")
                return False
            
            # Log verification results
            if success:
                self.logger.info(f"Archive verification successful: {archive_path}")
                self.logger.debug(f"Checksum: {result.get('checksum', 'N/A')}")
            else:
                self.logger.error(f"Archive verification failed: {archive_path}")
                for error in result.get("errors", []):
                    self.logger.error(f"  - {error}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Archive verification error: {e}")
            return False
    
    def create_verified_backup(self, site_name: str, db_file: str, files_dir: str) -> bool:
        """Create backup archives with full verification.
        
        Args:
            site_name: Name of the WordPress site
            db_file: Path to database dump file
            files_dir: Directory containing synced files
            
        Returns:
            True if backup creation and verification successful
            
        Raises:
            BackupStorageError: If backup creation or verification fails
        """
        timestamp = self.generate_timestamp()
        
        try:
            # Create archives
            self.logger.info(f"Creating verified backup for {site_name}")
            db_archive = self.create_db_archive(site_name, db_file, timestamp)
            files_archive = self.create_files_archive(site_name, files_dir, timestamp)
            
            # Verify archives
            db_result = self.verifier.verify_database_archive(db_archive)
            files_result = self.verifier.verify_files_archive(files_archive)
            
            # Check verification results
            if not (db_result["archive_valid"] and db_result["sql_valid"]):
                error_msg = f"Database backup verification failed: {db_result['errors']}"
                self.logger.error(error_msg)
                raise BackupStorageError(error_msg)
            
            if not files_result["archive_valid"]:
                error_msg = f"Files backup verification failed: {files_result['errors']}"
                self.logger.error(error_msg)
                raise BackupStorageError(error_msg)
            
            # Save checksums
            self.verifier.save_checksums(
                str(self.backup_dir), site_name, timestamp,
                db_result["checksum"], files_result["checksum"]
            )
            
            self.logger.info(f"Verified backup completed for {site_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Verified backup failed for {site_name}: {e}")
            # Cleanup any partially created archives
            try:
                if 'db_archive' in locals() and Path(db_archive).exists():
                    Path(db_archive).unlink()
                if 'files_archive' in locals() and Path(files_archive).exists():
                    Path(files_archive).unlink()
            except Exception:
                pass
            raise BackupStorageError(f"Verified backup failed: {e}")
    
    def cleanup_old_backups(self, site_name: str, retention_days: int):
        """Remove backup archives older than retention period.
        
        Args:
            site_name: Name of the WordPress site
            retention_days: Number of days to retain backups
        """
        site_backup_dir = self.backup_dir / site_name
        if not site_backup_dir.exists():
            return
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        removed_count = 0
        
        self.logger.info(f"Cleaning up backups older than {retention_days} days for {site_name}")
        
        # Find all backup archives for this site
        archive_patterns = [
            f"{site_name}_db_*.tar.gz",
            f"{site_name}_files_*.tar.gz"
        ]
        
        for pattern in archive_patterns:
            for archive_path in site_backup_dir.glob(pattern):
                try:
                    # Extract timestamp from filename
                    timestamp_str = self._extract_timestamp_from_filename(archive_path.name)
                    archive_date = datetime.strptime(timestamp_str, "%Y-%m-%d_%H-%M-%S")
                    
                    # Remove if older than retention period
                    if archive_date < cutoff_date:
                        archive_path.unlink()
                        removed_count += 1
                        self.logger.info(f"Removed old backup: {archive_path.name}")
                        
                except (ValueError, OSError) as e:
                    self.logger.warning(f"Could not process {archive_path}: {e}")
        
        # Also cleanup old checksums
        checksum_file = site_backup_dir / f"{site_name}_checksums.json"
        if checksum_file.exists():
            self._cleanup_old_checksums(checksum_file, retention_days)
        
        self.logger.info(f"Cleaned up {removed_count} old backup files for {site_name}")
    
    def _extract_timestamp_from_filename(self, filename: str) -> str:
        """Extract timestamp from backup filename.
        
        Args:
            filename: Backup archive filename
            
        Returns:
            Timestamp string
            
        Raises:
            ValueError: If no valid timestamp found
        """
        # Expected format: sitename_type_YYYY-MM-DD_HH-MM-SS.tar.gz
        pattern = r'\\d{4}-\\d{2}-\\d{2}_\\d{2}-\\d{2}-\\d{2}'
        match = re.search(pattern, filename)
        if match:
            return match.group(0)
        else:
            raise ValueError(f"No timestamp found in filename: {filename}")
    
    def _cleanup_old_checksums(self, checksum_file: Path, retention_days: int):
        """Remove old entries from checksum file.
        
        Args:
            checksum_file: Path to checksums JSON file
            retention_days: Retention period in days
        """
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        try:
            with open(checksum_file, 'r') as f:
                checksums = json.load(f)
            
            # Filter out old entries
            updated_checksums = {}
            for timestamp, data in checksums.items():
                try:
                    archive_date = datetime.strptime(timestamp, "%Y-%m-%d_%H-%M-%S")
                    if archive_date >= cutoff_date:
                        updated_checksums[timestamp] = data
                except ValueError:
                    # Keep entries with invalid timestamps for manual review
                    updated_checksums[timestamp] = data
            
            # Save updated checksums
            with open(checksum_file, 'w') as f:
                json.dump(updated_checksums, f, indent=2, sort_keys=True)
                
        except (json.JSONDecodeError, IOError) as e:
            self.logger.warning(f"Could not cleanup old checksums: {e}")
    
    def is_first_backup(self, site_name: str) -> bool:
        """Check if this is the first backup for a site.
        
        Args:
            site_name: Name of the WordPress site
            
        Returns:
            True if this is the first backup, False otherwise
        """
        site_backup_dir = self.backup_dir / site_name
        
        # No backup directory = first backup
        if not site_backup_dir.exists():
            return True
        
        # No files archives = first backup
        files_pattern = f"{site_name}_files_*.tar.gz"
        existing_files = list(site_backup_dir.glob(files_pattern))
        
        return len(existing_files) == 0
    
    def get_backup_summary(self, site_name: Optional[str] = None) -> Dict:
        """Get summary of backups.
        
        Args:
            site_name: Optional site name to filter by
            
        Returns:
            Dictionary with backup statistics
        """
        summary = {
            "total_sites": 0,
            "total_backups": 0,
            "total_size_bytes": 0,
            "sites": {}
        }
        
        # Determine which sites to check
        if site_name:
            site_dirs = [self.backup_dir / site_name] if (self.backup_dir / site_name).exists() else []
        else:
            site_dirs = [d for d in self.backup_dir.iterdir() if d.is_dir()]
        
        for site_dir in site_dirs:
            site_name = site_dir.name
            site_info = {
                "backup_count": 0,
                "latest_backup": None,
                "total_size_bytes": 0
            }
            
            # Count archives and calculate sizes
            for archive_pattern in [f"{site_name}_*.tar.gz"]:
                for archive_path in site_dir.glob(archive_pattern):
                    site_info["backup_count"] += 1
                    size = archive_path.stat().st_size
                    site_info["total_size_bytes"] += size
                    summary["total_size_bytes"] += size
                    
                    # Track latest backup
                    try:
                        timestamp = self._extract_timestamp_from_filename(archive_path.name)
                        if not site_info["latest_backup"] or timestamp > site_info["latest_backup"]:
                            site_info["latest_backup"] = timestamp
                    except ValueError:
                        pass
            
            if site_info["backup_count"] > 0:
                summary["sites"][site_name] = site_info
                summary["total_backups"] += site_info["backup_count"]
        
        summary["total_sites"] = len(summary["sites"])
        return summary