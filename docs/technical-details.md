# Technical Implementation Details

## Technology Stack

### Core Technologies
- **Language**: Python 3.8+
- **SSH/SFTP Library**: Paramiko
- **File Synchronization**: rsync (system utility)
- **Compression**: Built-in tarfile/gzipfile modules
- **Configuration**: JSON
- **Logging**: Python logging module with file and console handlers

### Required Python Packages
```
paramiko>=3.4.0          # SSH client library
cryptography>=41.0.0     # SSH key handling (required by paramiko)
```

### Optional Dependencies
```
# Currently none - all dependencies are required
```

### System Dependencies
```bash
# Required system utilities
rsync                    # File synchronization
mysqldump               # Database backup (on remote systems)
gzip/tar                # Compression utilities
ssh                     # SSH client
```

## Configuration Schema

### Configuration File (config.json)
```json
{
  "backup_dir": "/opt/wp-backups",
  "retention_days": 30,
  "log_level": "INFO",
  "log_file": "/var/log/wp-backup.log",
  "sites": [
    {
      "name": "example-com",
      "description": "Main company website",
      "ssh_host": "server1.provider.com",
      "ssh_port": 22,
      "ssh_user": "user1",
      "ssh_key": "~/.ssh/wp-backup-key",
      "web_root": "/var/www/html",
      "wp_config_path": "/var/www/html/wp-config.php",
      "retention_days": 60,
      "exclude_patterns": ["*.log", "wp-content/cache/*"]
    }
  ]
}
```

### Configuration Field Definitions
- **backup_dir**: Local directory for storing backup archives
- **retention_days**: Global default for cleanup (can be overridden per site)
- **log_level**: Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- **log_file**: Path to log file (will be created if doesn't exist)
- **sites[].name**: Unique identifier used in archive filenames (filesystem-safe)
- **sites[].description**: Human-readable description (optional)
- **sites[].ssh_***: SSH connection parameters
- **sites[].web_root**: WordPress installation directory
- **sites[].wp_config_path**: Path to wp-config.php (defaults to web_root/wp-config.php)
- **sites[].exclude_patterns**: rsync exclusion patterns for files
- **sites[].retention_days**: Site-specific retention (overrides global)

### Configuration Validation
The system validates:
- Required fields presence and types
- Site names are filesystem-safe (letters, numbers, hyphens, underscores, dots)
- SSH port ranges (1-65535)
- Retention days are positive integers
- SSH key file existence and permissions
- Backup directory write access

## Command Line Interface

### Main Script: `wp-backup.py`

```bash
# Basic usage
python wp-backup.py [OPTIONS]

# Available options:
--config, -c PATH        # Configuration file path (default: config.json)
--site, -s NAME          # Backup specific site only
--dry-run, -n            # Test without performing backup
--summary                # Show backup statistics
--validate               # Validate configuration only
--verbose, -v            # Increase verbosity (-v, -vv, -vvv)
--quiet, -q              # Suppress output except errors
--help, -h               # Show help message
```

### Usage Examples

```bash
# Validate configuration
python wp-backup.py --validate

# Test all sites without backing up
python wp-backup.py --dry-run

# Backup all configured sites
python wp-backup.py

# Backup only specific site
python wp-backup.py --site example-com

# Show backup statistics
python wp-backup.py --summary

# Use custom config file with verbose output
python wp-backup.py --config /path/to/config.json --verbose

# Quiet mode (errors only)
python wp-backup.py --quiet
```

### Exit Codes
- `0`: Success
- `1`: General error (configuration, backup failure)
- `130`: Interrupted by user (Ctrl+C)

### Output Format

**Normal operation:**
```
INFO: Starting backup process for 2 site(s)
INFO: Processing site: example-com
INFO: SSH connection successful to server1.provider.com
INFO: Creating database backup for example-com
INFO: Starting file synchronization for example-com
INFO: Creating and verifying backup archives for example-com
INFO: Backup completed successfully for example-com
INFO: Backup process completed: 2/2 sites successful
```

**Summary output:**
```
Backup Summary
==================================================
Total sites: 2
Total backups: 12
Total size: 245.3 MB

Site: example-com
  Backups: 8
  Size: 156.7 MB
  Latest: 2024-12-14_10-30-15

Site: blog-site
  Backups: 4
  Size: 88.6 MB
  Latest: 2024-12-13_22-15-30
```
```bash
# Generate SSH key pair for backup operations
ssh-keygen -t ed25519 -f ~/.ssh/wp-backup-key -C "wp-backup-tool"

# Add public key to remote server
ssh-copy-id -i ~/.ssh/wp-backup-key.pub user@remote-server

# Set proper permissions
chmod 600 ~/.ssh/wp-backup-key
chmod 644 ~/.ssh/wp-backup-key.pub
```

## Core Module Specifications

### 1. BackupController Class
```python
class BackupController:
    """Main orchestrator for WordPress backup operations."""
    
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = None
        self.logger = None
    
    def run_backup(self, site_filter: str = None) -> bool:
        """Execute backup for all sites or specific site."""
        pass
    
    def setup_logging(self) -> logging.Logger:
        """Configure logging based on config settings."""
        pass
    
    def backup_site(self, site_config: dict) -> bool:
        """Backup single WordPress site."""
        pass
```

### 2. ConfigLoader Class
```python
class ConfigLoader:
    """Simple configuration file loader and validator."""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
    
    def load_config(self) -> dict:
        """Load and validate configuration file."""
        pass
    
    def validate_config(self, config: dict) -> bool:
        """Validate configuration schema and required fields."""
        pass
    
    def get_sites(self) -> List[dict]:
        """Return list of configured WordPress sites."""
        pass
```

### 3. SSHClient Class  
```python
class SSHClient:
    """Handle all SSH operations for remote WordPress sites."""
    
    def __init__(self, host: str, username: str, key_path: str, port: int = 22):
        self.host = host
        self.username = username
        self.key_path = key_path
        self.port = port
        self.client = None
    
    def connect_with_retry(self) -> bool:
        """Establish SSH connection with 5 retries at 5s intervals."""
        pass
    
    def parse_wp_config(self, wp_config_path: str) -> dict:
        """Parse wp-config.php file for database credentials."""
        pass
    
    def execute_mysqldump(self, db_config: dict, output_file: str) -> bool:
        """Execute mysqldump and download result."""
        pass
    
    def execute_rsync(self, remote_path: str, local_path: str, 
                      exclude_patterns: List[str] = None, 
                      is_first_backup: bool = False) -> bool:
        """Execute rsync file synchronization."""
        pass
    
    def close(self):
        """Close SSH connection."""
        pass
```

### 4. BackupStorage Class
```python
class BackupStorage:
    """Local backup file management and archiving."""
    
    def __init__(self, backup_dir: str):
        self.backup_dir = backup_dir
    
    def create_db_archive(self, site_name: str, dump_file: str) -> str:
        """Create timestamped database archive."""
        pass
    
    def create_files_archive(self, site_name: str, files_dir: str) -> str:
        """Create timestamped files archive."""
        pass
    
    def generate_timestamp(self) -> str:
        """Generate YYYY-MM-DD_HH-MM-SS timestamp."""
        pass
    
    def verify_archive_integrity(self, archive_path: str) -> bool:
        """Verify archive integrity and generate checksums."""
        pass
    
    def cleanup_old_backups(self, site_name: str, retention_days: int):
        """Remove backups older than retention period."""
        pass
```

## Database Integration

### WordPress Configuration Parsing
```python
def parse_wp_config(self, config_content: str) -> dict:
    """
    Parse wp-config.php content to extract database credentials.
    
    Expected format:
    define('DB_NAME', 'database_name');
    define('DB_USER', 'username');
    define('DB_PASSWORD', 'password');
    define('DB_HOST', 'localhost');
    """
    import re
    
    patterns = {
        'DB_NAME': r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        'DB_USER': r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        'DB_PASSWORD': r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        'DB_HOST': r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]"
    }
    
    credentials = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, config_content, re.IGNORECASE)
        if match:
            credentials[key.lower()] = match.group(1)
    
    return credentials
```

### MySQL Dump Command Generation
```python
def build_mysqldump_command(self, db_config: dict, output_path: str) -> str:
    """Build mysqldump command with proper options."""
    
    base_cmd = "mysqldump"
    options = [
        "--single-transaction",     # InnoDB consistency
        "--routines",              # Include stored procedures
        "--triggers",              # Include triggers
        "--complete-insert",       # Full INSERT statements
        "--extended-insert",       # Multiple rows per INSERT
        "--lock-tables=false",     # Don't lock tables
        "--add-drop-table",        # Add DROP TABLE statements
        "--disable-keys"           # Disable key checks
    ]
    
    host_param = f"--host={db_config['db_host']}"
    user_param = f"--user={db_config['db_user']}"
    password_param = f"--password={db_config['db_password']}"
    
    command = f"{base_cmd} {' '.join(options)} {host_param} {user_param} {password_param} {db_config['db_name']} > {output_path}"
    
    return command
```

### Rsync Strategy (WSL-Compatible)

```python
def build_rsync_command(self, remote_path: str, local_path: str, 
                        exclude_patterns: List[str] = None,
                        is_first_backup: bool = False) -> str:
    """Build rsync command optimized for incremental backups."""
    
    # Base options for all rsync operations
    base_options = [
        "-avz",              # Archive mode + verbose + compress
        "--stats",           # Show transfer statistics  
        "--human-readable",  # Human-readable output
        "--progress",        # Show progress during transfer
        "--partial",         # Keep partially transferred files
        "--timeout=300"      # 5-minute timeout
    ]
    
    # Incremental options (skip for first backup)
    if not is_first_backup:
        base_options.extend([
            "--update",       # Skip files newer on destination
            "--existing",     # Only update files that exist in dest
            "--ignore-times"  # Don't rely on timestamps alone
        ])
    
    # Add exclusion patterns
    if exclude_patterns:
        for pattern in exclude_patterns:
            base_options.append(f"--exclude={pattern}")
    
    # Standard WordPress exclusions
    base_options.extend([
        "--exclude=*.log",
        "--exclude=wp-content/cache/",
        "--exclude=wp-content/backup*/"
    ])
    
    # SSH options for secure connection
    ssh_opts = [
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=~/.ssh/known_hosts",
        "-o", "ConnectTimeout=30"
    ]
    
    ssh_command = f"ssh {' '.join(ssh_opts)}"
    
    return f"rsync {' '.join(base_options)} -e '{ssh_command}' {self.username}@{self.host}:{remote_path}/ {local_path}/"
```

### First Backup Detection
```python
def is_first_backup(self, site_name: str) -> bool:
    """Check if this is the first backup for a site."""
    
    site_backup_dir = os.path.join(self.backup_dir, site_name)
    
    # No backup directory = first backup
    if not os.path.exists(site_backup_dir):
        return True
    
    # No files archives = first backup  
    files_pattern = f"{site_name}_files_*.tar.gz"
    existing_files = glob.glob(os.path.join(site_backup_dir, files_pattern))
    
    return len(existing_files) == 0
```

### Incremental Backup Strategy
- **First backup**: Full rsync without `--update` flag
- **Subsequent backups**: Use `--update` to only transfer newer files
- **File comparison**: Based on modification time and size (not checksums during transfer)
- **Storage**: Each backup creates separate timestamped archive
- **No hard links**: Avoids WSL compatibility issues

### Comprehensive Backup Verification

```python
import hashlib
import tarfile
import gzip
import sqlite3

class BackupVerifier:
    """Full verification of backup archives with checksums."""
    
    def verify_database_archive(self, archive_path: str) -> dict:
        """Verify database archive integrity and content."""
        
        result = {
            "archive_valid": False,
            "sql_valid": False, 
            "checksum": None,
            "errors": []
        }
        
        try:
            # 1. Verify tar.gz archive integrity
            with tarfile.open(archive_path, 'r:gz') as tar:
                tar.getmembers()  # This will fail if corrupted
            result["archive_valid"] = True
            
            # 2. Extract and validate SQL content
            with tarfile.open(archive_path, 'r:gz') as tar:
                sql_file = tar.extractfile(tar.getmembers()[0])
                sql_content = sql_file.read().decode('utf-8')
                
                # Basic SQL validation
                if self._validate_sql_syntax(sql_content):
                    result["sql_valid"] = True
                else:
                    result["errors"].append("Invalid SQL syntax")
            
            # 3. Generate SHA256 checksum
            result["checksum"] = self._calculate_file_checksum(archive_path)
            
        except Exception as e:
            result["errors"].append(f"Archive verification failed: {str(e)}")
        
        return result
    
    def verify_files_archive(self, archive_path: str, expected_file_count: int = None) -> dict:
        """Verify files archive integrity and content."""
        
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
                result["file_count"] = len(members)
            result["archive_valid"] = True
            
            # 2. Validate file count if expected count provided
            if expected_file_count and result["file_count"] < expected_file_count * 0.95:
                result["errors"].append(f"File count too low: {result['file_count']} < {expected_file_count}")
            
            # 3. Generate SHA256 checksum
            result["checksum"] = self._calculate_file_checksum(archive_path)
            
        except Exception as e:
            result["errors"].append(f"Archive verification failed: {str(e)}")
        
        return result
    
    def _validate_sql_syntax(self, sql_content: str) -> bool:
        """Basic SQL syntax validation for MySQL dumps."""
        
        required_patterns = [
            "-- MySQL dump",
            "CREATE TABLE",
            "INSERT INTO"
        ]
        
        for pattern in required_patterns:
            if pattern not in sql_content:
                return False
        
        # Check for common corruption signs
        corruption_signs = [
            "ERROR 1",
            "Access denied",
            "Connection failed"
        ]
        
        for sign in corruption_signs:
            if sign in sql_content:
                return False
                
        return True
    
    def _calculate_file_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file."""
        
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        
        return hash_sha256.hexdigest()
    
    def save_checksums(self, site_name: str, timestamp: str, 
                       db_checksum: str, files_checksum: str):
        """Save checksums to verification file."""
        
        checksum_file = os.path.join(self.backup_dir, site_name, f"{site_name}_checksums.json")
        
        # Load existing checksums
        checksums = {}
        if os.path.exists(checksum_file):
            with open(checksum_file, 'r') as f:
                checksums = json.load(f)
        
        # Add new checksums
        checksums[timestamp] = {
            "database": db_checksum,
            "files": files_checksum,
            "verified_at": datetime.now().isoformat()
        }
        
        # Save updated checksums
        with open(checksum_file, 'w') as f:
            json.dump(checksums, f, indent=2)
```

### Verification Integration
```python
def create_verified_backup(self, site_name: str, db_file: str, files_dir: str) -> bool:
    """Create backup archives with full verification."""
    
    timestamp = self.generate_timestamp()
    verifier = BackupVerifier()
    
    # Create archives
    db_archive = self.create_db_archive(site_name, db_file, timestamp)
    files_archive = self.create_files_archive(site_name, files_dir, timestamp)
    
    # Verify archives
    db_result = verifier.verify_database_archive(db_archive)
    files_result = verifier.verify_files_archive(files_archive)
    
    # Check verification results
    if not (db_result["archive_valid"] and db_result["sql_valid"]):
        self.logger.error(f"Database backup verification failed: {db_result['errors']}")
        return False
        
    if not files_result["archive_valid"]:
        self.logger.error(f"Files backup verification failed: {files_result['errors']}")
        return False
    
    # Save checksums
    verifier.save_checksums(site_name, timestamp, 
                           db_result["checksum"], 
                           files_result["checksum"])
    
    self.logger.info(f"Backup verification successful for {site_name}")
    return True
```

### Logging Configuration
```python
import logging
from logging.handlers import RotatingFileHandler

def setup_logging(log_level: str, log_file: str):
    """Configure logging with file and console handlers."""
    
    # Create logger
    logger = logging.getLogger('wp-backup')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    
    file_handler.setFormatter(file_formatter)
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger
```

### Exception Handling Strategy
```python
class BackupError(Exception):
    """Base exception for backup operations."""
    pass

class SSHConnectionError(BackupError):
    """SSH connection related errors."""
    pass

class DatabaseBackupError(BackupError):
    """Database backup related errors."""
    pass

class FileBackupError(BackupError):
    """File backup related errors."""
    pass

class ConfigurationError(BackupError):
    """Configuration related errors."""
    pass
```

## Performance Considerations

### Memory Management
- Stream large file transfers to avoid memory issues
- Use temporary files for intermediate operations
- Clean up resources properly after each instance

### Network Optimization
- Configure SSH connection multiplexing
- Use compression for data transfers
- Implement connection pooling for multiple operations

### Storage Optimization
- Implement backup deduplication strategies
- Use appropriate compression algorithms
- Monitor disk space before backup operations

## Logging and Monitoring

### Log Levels and Output

```python
# Log levels (set in config.json)
DEBUG    # Detailed debugging info, command outputs
INFO     # General operational messages (default)
WARNING  # Non-fatal issues, missing optional fields
ERROR    # Errors that don't stop the process
CRITICAL # Fatal errors that stop execution
```

### Log File Format

```
2024-12-14 10:30:15 - wp-backup - INFO - Starting backup process for 2 site(s)
2024-12-14 10:30:15 - wp-backup - INFO - Processing site: example-com
2024-12-14 10:30:16 - ssh_client - INFO - SSH connection successful to server1.provider.com
2024-12-14 10:30:17 - backup_controller - INFO - Creating database backup for example-com
2024-12-14 10:30:25 - ssh_client - INFO - Database dump completed: /tmp/example-com_db.sql
2024-12-14 10:30:26 - backup_controller - INFO - Starting file synchronization for example-com
2024-12-14 10:32:15 - ssh_client - INFO - File synchronization completed successfully
2024-12-14 10:32:16 - backup_storage - INFO - Creating database archive: example-com_db_2024-12-14_10-30-15.tar.gz
2024-12-14 10:32:18 - backup_storage - INFO - Archive verification successful: /opt/wp-backups/example-com/example-com_db_2024-12-14_10-30-15.tar.gz
```

### Error Handling Examples

**SSH Connection Failure:**
```
2024-12-14 10:30:15 - ssh_client - WARNING - SSH connection attempt 1 failed: Connection refused
2024-12-14 10:30:15 - ssh_client - INFO - Waiting 5 seconds before retry...
2024-12-14 10:30:21 - ssh_client - INFO - SSH connection successful to server1.provider.com
```

**Database Access Error:**
```
2024-12-14 10:30:25 - ssh_client - ERROR - mysqldump failed: Access denied for user 'dbuser'@'localhost'
2024-12-14 10:30:25 - backup_controller - ERROR - Site example-com backup failed
2024-12-14 10:30:25 - backup_controller - INFO - Processing site: next-site
```

**Archive Verification Failure:**
```
2024-12-14 10:32:18 - backup_storage - ERROR - Archive verification failed: /path/to/archive.tar.gz
2024-12-14 10:32:18 - backup_storage - ERROR -   - Invalid SQL syntax or content
2024-12-14 10:32:18 - backup_controller - ERROR - Archive creation or verification failed for example-com
```

### Monitoring Integration

The tool supports monitoring integration through:

1. **Exit codes** for script automation
2. **Structured logging** for log aggregation
3. **JSON summary** output for parsing
4. **File-based checksums** for integrity monitoring

**Example monitoring script:**
```bash
#!/bin/bash
# Simple monitoring wrapper

python wp-backup.py --quiet
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ WordPress backup completed successfully"
    # Send success notification
else
    echo "✗ WordPress backup failed (exit code: $EXIT_CODE)"
    # Send alert notification
    tail -20 /var/log/wp-backup.log
fi

exit $EXIT_CODE
```

```python
def cleanup_old_backups(self, site_name: str, retention_days: int):
    """Remove backup archives older than retention period."""
    
    site_backup_dir = os.path.join(self.backup_dir, site_name)
    if not os.path.exists(site_backup_dir):
        return
    
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    removed_count = 0
    
    # Find all backup archives for this site
    archive_patterns = [
        f"{site_name}_db_*.tar.gz",
        f"{site_name}_files_*.tar.gz"
    ]
    
    for pattern in archive_patterns:
        for archive_path in glob.glob(os.path.join(site_backup_dir, pattern)):
            try:
                # Extract timestamp from filename
                filename = os.path.basename(archive_path)
                timestamp_str = self._extract_timestamp_from_filename(filename)
                archive_date = datetime.strptime(timestamp_str, "%Y-%m-%d_%H-%M-%S")
                
                # Remove if older than retention period
                if archive_date < cutoff_date:
                    os.remove(archive_path)
                    removed_count += 1
                    self.logger.info(f"Removed old backup: {filename}")
                    
            except (ValueError, OSError) as e:
                self.logger.warning(f"Could not process {archive_path}: {e}")
    
    # Also cleanup old checksums
    checksum_file = os.path.join(site_backup_dir, f"{site_name}_checksums.json")
    if os.path.exists(checksum_file):
        self._cleanup_old_checksums(checksum_file, retention_days)
    
    self.logger.info(f"Cleaned up {removed_count} old backup files for {site_name}")

def _extract_timestamp_from_filename(self, filename: str) -> str:
    """Extract timestamp from backup filename."""
    # Expected format: sitename_type_YYYY-MM-DD_HH-MM-SS.tar.gz
    import re
    pattern = r'\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}'
    match = re.search(pattern, filename)
    if match:
        return match.group(0)
    else:
        raise ValueError(f"No timestamp found in filename: {filename}")

def _cleanup_old_checksums(self, checksum_file: str, retention_days: int):
    """Remove old entries from checksum file."""
    
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    
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
        json.dump(updated_checksums, f, indent=2)
```

### Retention Policy Examples
- **30 days**: Keep ~30 daily backups per site
- **60 days**: Keep ~60 daily backups (for critical sites)
- **7 days**: Keep 1 week of backups (for test sites)

Retention is applied **before** each new backup to ensure space availability.

### SSH Security
```python
def validate_ssh_key(self, key_path: str) -> bool:
    """Validate SSH private key format and permissions."""
    
    import stat
    import os
    
    # Check file exists
    if not os.path.exists(key_path):
        return False
    
    # Check file permissions (should be 600)
    file_stat = os.stat(key_path)
    if file_stat.st_mode & 0o777 != 0o600:
        return False
    
    # Validate key format
    try:
        from paramiko import RSAKey, Ed25519Key, ECDSAKey
        
        # Try different key formats
        for key_class in [RSAKey, Ed25519Key, ECDSAKey]:
            try:
                key_class.from_private_key_file(key_path)
                return True
            except:
                continue
        
        return False
    except ImportError:
        return False
```

### Configuration Security
- Restrict configuration file permissions (600)
- Validate all input parameters
- Sanitize paths and commands
- Use secure temporary file creation

## Troubleshooting

### Common Issues

**1. SSH Connection Failures**
```bash
# Test SSH connection manually
ssh -i ~/.ssh/wp-backup-key user@server.com

# Check SSH key permissions
ls -la ~/.ssh/wp-backup-key  # Should be -rw-------
```

**2. Permission Errors**
```bash
# Fix SSH key permissions
chmod 600 ~/.ssh/wp-backup-key

# Check backup directory permissions
ls -la /opt/wp-backups  # Should be writable by current user
```

**3. mysqldump Failures**
- Verify database credentials in wp-config.php
- Ensure mysqldump is installed on remote server
- Check database user has SELECT, LOCK TABLES privileges

**4. rsync Issues**
- Verify rsync is installed on both local and remote systems
- Check exclude patterns in configuration
- Test rsync manually:
  ```bash
  rsync -avz -e "ssh -i ~/.ssh/wp-backup-key" user@server:/var/www/html/ /tmp/test/
  ```

**5. WSL-Specific Issues**
- Use WSL filesystem paths for backups: `/home/user/backups` not `/mnt/c/backups`
- Ensure SSH keys are in WSL filesystem with correct permissions
- Install required utilities in WSL: `sudo apt install rsync openssh-client`

### Debug Mode

Enable verbose logging for troubleshooting:
```bash
# Maximum verbosity
python wp-backup.py --verbose --verbose

# Test specific site
python wp-backup.py --site problem-site --dry-run --verbose
```

### Performance Optimization

**For Large Sites:**
- Use more specific exclude patterns
- Consider backup scheduling during off-peak hours
- Monitor disk space on backup destination
- Implement backup rotation for very large sites

**Network Optimization:**
- Use SSH connection multiplexing for multiple operations
- Configure rsync bandwidth limits if needed
- Consider compression settings based on file types