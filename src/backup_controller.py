"""
WordPress Backup Tool Controller

Main orchestrator that coordinates all backup operations.
"""

import logging
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config_loader import ConfigLoader, ConfigurationError
from .ssh_client import SSHClient, SSHConnectionError, RemoteOperationError
from .backup_storage import BackupStorage, BackupStorageError

class BackupError(Exception):
    """General backup operation errors."""
    pass

class BackupController:
    """Main orchestrator for WordPress backup operations."""
    
    def __init__(self, config_file: str, verbose_level: int = 0):
        """Initialize backup controller.
        
        Args:
            config_file: Path to configuration file
            verbose_level: Verbose logging level (0=normal, 1=verbose, 2=debug)
        """
        self.config_file = config_file
        self.verbose_level = verbose_level
        self.config_loader = None
        self.config = None
        self.storage = None
        self.logger = None
        self.temp_dir = None
    
    def run_backup(self, site_filter: Optional[str] = None, dry_run: bool = False) -> bool:
        """Execute backup for all sites or specific site.
        
        Args:
            site_filter: Optional site name to backup (if None, backup all)
            dry_run: If True, validate configuration and connections without backing up
            
        Returns:
            True if all backups successful, False if any failed
            
        Raises:
            BackupError: If configuration or setup fails
        """
        try:
            # Initialize
            self._initialize()
            
            # Get sites to backup
            if site_filter:
                site_config = self.config_loader.get_site_by_name(site_filter)
                if not site_config:
                    raise BackupError(f"Site '{site_filter}' not found in configuration")
                sites = [site_config]
            else:
                sites = self.config_loader.get_sites()
            
            if not sites:
                raise BackupError("No sites configured for backup")
            
            self.logger.info(f"Starting backup process for {len(sites)} site(s)")
            if dry_run:
                self.logger.info("DRY RUN MODE - No actual backups will be performed")
            
            # Process each site
            success_count = 0
            total_count = len(sites)
            
            for site in sites:
                site_name = site['name']
                try:
                    self.logger.info(f"===>>> Processing site: {site_name}")
                    
                    if dry_run:
                        success = self._test_site_connection(site)
                    else:
                        success = self.backup_site(site)
                    
                    if success:
                        success_count += 1
                        self.logger.info(f"Site {site_name} backup completed successfully")
                    else:
                        self.logger.error(f"Site {site_name} backup failed")
                        
                except Exception as e:
                    self.logger.error(f"Site {site_name} backup failed with exception: {e}")
            
            # Summary
            self.logger.info(f"Backup process completed: {success_count}/{total_count} sites successful")
            
            return success_count == total_count
            
        except Exception as e:
            self.logger.error(f"Backup process failed: {e}")
            raise BackupError(f"Backup process failed: {e}")
        
        finally:
            self._cleanup()
    
    def backup_site(self, site_config: Dict) -> bool:
        """Backup single WordPress site.
        
        Args:
            site_config: Site configuration dictionary
            
        Returns:
            True if backup successful, False otherwise
        """
        site_name = site_config['name']
        ssh_client = None
        
        try:
            self.logger.info(f"Starting backup for site: {site_name}")
            
            # Create SSH client
            ssh_client = SSHClient(
                host=site_config['ssh_host'],
                username=site_config['ssh_user'], 
                key_path=site_config['ssh_key'],
                port=site_config.get('ssh_port', 22)
            )
            
            # Connect with retry
            if not ssh_client.connect_with_retry():
                self.logger.error(f"Failed to establish SSH connection for {site_name}")
                return False
            
            # Test connection
            if not ssh_client.test_connection():
                self.logger.error(f"SSH connection test failed for {site_name}")
                return False
            
            # Parse WordPress configuration
            wp_config_path = site_config.get('wp_config_path', f"{site_config['web_root']}/htdocs/wp-config.php")
            db_config = ssh_client.parse_wp_config(wp_config_path)
            
            # Create temporary directory for this backup
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Database backup
                db_dump_file = temp_path / f"{site_name}_db_temp.sql"
                self.logger.info(f"Creating database backup for {site_name}")
                
                if not ssh_client.execute_mysqldump(db_config, str(db_dump_file), temp_dir):
                    self.logger.error(f"Database backup failed for {site_name}")
                    return False
                
                # Files backup
                files_temp_dir = temp_path / "files"
                files_temp_dir.mkdir()
                
                self.logger.info(f"Starting file synchronization for {site_name}")
                
                is_first = self.storage.is_first_backup(site_name)
                if is_first:
                    self.logger.info(f"First backup detected for {site_name} - performing full sync")
                
                exclude_patterns = site_config.get('exclude_patterns', [])
                
                if not ssh_client.execute_rsync(
                    remote_path=site_config['web_root'],
                    local_path=str(files_temp_dir),
                    exclude_patterns=exclude_patterns,
                    is_first_backup=is_first
                ):
                    self.logger.error(f"File synchronization failed for {site_name}")
                    return False
                
                # Create verified backup archives
                self.logger.info(f"Creating and verifying backup archives for {site_name}")
                
                if not self.storage.create_verified_backup(
                    site_name=site_name,
                    db_file=str(db_dump_file),
                    files_dir=str(files_temp_dir)
                ):
                    self.logger.error(f"Archive creation or verification failed for {site_name}")
                    return False
                
                # Cleanup old backups
                retention_days = site_config.get('retention_days', self.config['retention_days'])
                self.logger.info(f"Cleaning up old backups for {site_name} (retention: {retention_days} days)")
                self.storage.cleanup_old_backups(site_name, retention_days)
                
                self.logger.info(f"Backup completed successfully for {site_name}")
                return True
            
        except SSHConnectionError as e:
            self.logger.error(f"SSH connection error for {site_name}: {e}")
            return False
        except RemoteOperationError as e:
            self.logger.error(f"Remote operation error for {site_name}: {e}")
            return False
        except BackupStorageError as e:
            self.logger.error(f"Storage error for {site_name}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during backup of {site_name}: {e}")
            return False
        finally:
            if ssh_client:
                ssh_client.close()
    
    def _test_site_connection(self, site_config: Dict) -> bool:
        """Test SSH connection and basic functionality for a site.
        
        Args:
            site_config: Site configuration dictionary
            
        Returns:
            True if all tests pass, False otherwise
        """
        site_name = site_config['name']
        ssh_client = None
        
        try:
            self.logger.info(f"Testing connection for site: {site_name}")
            
            # Create SSH client
            ssh_client = SSHClient(
                host=site_config['ssh_host'],
                username=site_config['ssh_user'],
                key_path=site_config['ssh_key'],
                port=site_config.get('ssh_port', 22)
            )
            
            # Test connection
            if not ssh_client.connect_with_retry():
                self.logger.error(f"SSH connection test failed for {site_name}")
                return False
            
            if not ssh_client.test_connection():
                self.logger.error(f"SSH functionality test failed for {site_name}")
                return False
            
            # Test wp-config.php access
            wp_config_path = site_config.get('wp_config_path', f"{site_config['web_root']}/wp-config.php")
            try:
                db_config = ssh_client.parse_wp_config(wp_config_path)
                self.logger.info(f"wp-config.php parsed successfully for {site_name}")
                self.logger.debug(f"Database: {db_config.get('db_name')} @ {db_config.get('db_host')}")
            except RemoteOperationError as e:
                self.logger.error(f"wp-config.php access failed for {site_name}: {e}")
                return False
            
            # Test database connectivity
            try:
                self.logger.info(f"Testing database connectivity for {site_name}")
                
                # Test if mysqldump is available
                exit_code, stdout, stderr = ssh_client.execute_command("which mysqldump")
                if exit_code != 0:
                    self.logger.error(f"mysqldump not found for {site_name}: {stderr}")
                    return False
                else:
                    mysqldump_path = stdout.strip()
                    self.logger.debug(f"mysqldump found at: {mysqldump_path}")
                
                # Test if mysql client is available
                exit_code, stdout, stderr = ssh_client.execute_command("which mysql")
                if exit_code != 0:
                    self.logger.error(f"mysql client not found for {site_name}: {stderr}")
                    return False
                else:
                    mysql_path = stdout.strip()
                    self.logger.debug(f"mysql client found at: {mysql_path}")
                
                # Get database credentials
                db_host = db_config.get('db_host', 'localhost')
                db_name = db_config.get('db_name')
                db_user = db_config.get('db_user')
                db_password = db_config.get('db_password')
                
                self.logger.debug(f"Testing database connection: {db_user}@{db_host}/{db_name}")
                
                # Test database connection using mysql client
                test_cmd = f"mysql -h {db_host} -u {db_user} -p'{db_password}' -e 'USE {db_name}; SELECT 1;' 2>/dev/null"
                exit_code, stdout, stderr = ssh_client.execute_command(test_cmd)
                
                if exit_code != 0:
                    # Try to get more detailed error info
                    detailed_cmd = f"mysql -h {db_host} -u {db_user} -p'{db_password}' -e 'USE {db_name}; SELECT 1;'"
                    _, _, detailed_stderr = ssh_client.execute_command(detailed_cmd)
                    self.logger.error(f"Database connection test failed for {site_name}: {detailed_stderr}")
                    return False
                
                self.logger.info(f"Database connectivity test passed for {site_name}")
                
                # Test mysqldump specifically (without actually dumping)
                self.logger.info(f"Testing mysqldump functionality for {site_name}")
                dump_test_cmd = f"mysqldump -h {db_host} -u {db_user} -p'{db_password}' --single-transaction --routines --triggers --where='1=0' {db_name} 2>/dev/null | head -20"
                exit_code, stdout, stderr = ssh_client.execute_command(dump_test_cmd)
                
                if exit_code != 0:
                    # Try to get more detailed error info
                    detailed_dump_cmd = f"mysqldump -h {db_host} -u {db_user} -p'{db_password}' --single-transaction --routines --triggers --where='1=0' {db_name}"
                    _, _, detailed_stderr = ssh_client.execute_command(detailed_dump_cmd)
                    self.logger.error(f"mysqldump test failed for {site_name}: {detailed_stderr}")
                    return False
                
                self.logger.info(f"mysqldump functionality test passed for {site_name}")
                
            except Exception as e:
                self.logger.error(f"Database connectivity test failed for {site_name}: {e}")
                return False
            
            # Test web root access
            web_root = site_config['web_root']
            exit_code, stdout, stderr = ssh_client.execute_command(f"ls -la {web_root}")
            if exit_code != 0:
                self.logger.error(f"Web root access failed for {site_name}: {stderr}")
                return False
            
            self.logger.info(f"Connection test passed for {site_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Connection test failed for {site_name}: {e}")
            return False
        finally:
            if ssh_client:
                ssh_client.close()
    
    def _initialize(self):
        """Initialize backup system components."""
        try:
            # Load configuration
            self.config_loader = ConfigLoader(self.config_file)
            self.config = self.config_loader.load_config()
            
            # Setup logging
            self.logger = self.setup_logging()
            
            # Initialize storage
            self.storage = BackupStorage(self.config['backup_dir'])
            
            self.logger.info("Backup system initialized successfully")
            
        except ConfigurationError as e:
            raise BackupError(f"Configuration error: {e}")
        except Exception as e:
            raise BackupError(f"Initialization failed: {e}")
    
    def setup_logging(self) -> logging.Logger:
        """Configure logging based on config settings.
        
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger('wp-backup')
        
        # Clear any existing handlers
        logger.handlers.clear()
        
        # Set log level - prioritize verbose level over config
        if self.verbose_level >= 2:
            logger.setLevel(logging.DEBUG)
            # Also set root logger to DEBUG to ensure all child loggers work
            logging.getLogger().setLevel(logging.DEBUG)
        elif self.verbose_level >= 1:
            logger.setLevel(logging.INFO)
            logging.getLogger().setLevel(logging.INFO)
        else:
            # Use config setting
            log_level = self.config.get('log_level', 'INFO')
            logger.setLevel(getattr(logging, log_level.upper()))
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        simple_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        
        # File handler
        log_file = self.config.get('log_file')
        if log_file:
            try:
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                
                file_handler = logging.FileHandler(log_file)
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(detailed_formatter)
                logger.addHandler(file_handler)
            except Exception as e:
                # Can't use logger yet since we're setting it up, use stderr
                import sys
                print(f"Warning: Could not setup file logging: {e}", file=sys.stderr)
        
        # Console handler with verbose level support
        console_handler = logging.StreamHandler()
        
        # Set console log level based on verbose flag
        if self.verbose_level >= 2:
            console_handler.setLevel(logging.DEBUG)
        elif self.verbose_level >= 1:
            console_handler.setLevel(logging.INFO)
        else:
            console_handler.setLevel(logging.INFO)
        
        console_handler.setFormatter(simple_formatter)
        logger.addHandler(console_handler)
        
        return logger
    
    def _cleanup(self):
        """Cleanup resources."""
        if self.temp_dir and Path(self.temp_dir).exists():
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Could not cleanup temporary directory: {e}")
        
        if self.logger:
            self.logger.info("Backup process cleanup completed")
    
    def get_backup_summary(self, site_name: Optional[str] = None) -> Dict:
        """Get backup summary information.
        
        Args:
            site_name: Optional site name to filter by
            
        Returns:
            Dictionary with backup statistics
            
        Raises:
            BackupError: If system not initialized
        """
        if not self.storage:
            # Initialize minimal system for summary
            try:
                self.config_loader = ConfigLoader(self.config_file)
                self.config = self.config_loader.load_config()
                self.storage = BackupStorage(self.config['backup_dir'])
            except Exception as e:
                raise BackupError(f"Failed to initialize for summary: {e}")
        
        return self.storage.get_backup_summary(site_name)
    
    def validate_configuration(self) -> Tuple[bool, List[str]]:
        """Validate configuration file and settings.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        try:
            # Load and validate config
            config_loader = ConfigLoader(self.config_file)
            config = config_loader.load_config()
            
            # Additional validation checks
            backup_dir = Path(config['backup_dir'])
            if not backup_dir.exists():
                try:
                    backup_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    errors.append(f"Cannot create backup directory {backup_dir}: {e}")
            
            if not backup_dir.is_dir():
                errors.append(f"Backup directory is not a directory: {backup_dir}")
            
            # Validate SSH keys exist
            for site in config['sites']:
                ssh_key = Path(site['ssh_key'])
                if not ssh_key.exists():
                    errors.append(f"SSH key not found for site '{site['name']}': {ssh_key}")
                elif not ssh_key.is_file():
                    errors.append(f"SSH key is not a file for site '{site['name']}': {ssh_key}")
            
            return len(errors) == 0, errors
            
        except ConfigurationError as e:
            errors.append(str(e))
            return False, errors
        except Exception as e:
            errors.append(f"Validation failed: {e}")
            return False, errors