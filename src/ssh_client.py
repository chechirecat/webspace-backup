"""
WordPress Backup Tool SSH Client

Handles SSH connections and all remote operations for WordPress backups.
"""

import paramiko
import time
import re
import logging
import os
from pathlib import Path
from typing import Dict, Tuple, List
import subprocess

class SSHConnectionError(Exception):
    """SSH connection related errors."""
    pass

class RemoteOperationError(Exception):
    """Remote operation related errors."""
    pass

class SSHClient:
    """Handle all SSH operations for remote WordPress sites."""
    
    def __init__(self, host: str, username: str, key_path: str, port: int = 22):
        """Initialize SSH client with connection parameters.
        
        Args:
            host: SSH hostname or IP address
            username: SSH username
            key_path: Path to SSH private key file
            port: SSH port (default: 22)
        """
        self.host = host
        self.username = username
        self.key_path = Path(key_path).expanduser().resolve()
        self.port = port
        self.client = None
        self.sftp = None
        self.logger = logging.getLogger(__name__)
    
    def connect_with_retry(self, max_retries: int = 5, retry_delay: int = 5) -> bool:
        """Establish SSH connection with retry logic.
        
        Args:
            max_retries: Maximum number of connection attempts (default: 5)
            retry_delay: Delay between retries in seconds (default: 5)
            
        Returns:
            True if connection successful, False otherwise
            
        Raises:
            SSHConnectionError: If all connection attempts fail
        """
        for attempt in range(1, max_retries + 1):
            try:
                self.logger.info(f"SSH connection attempt {attempt}/{max_retries} to {self.username}@{self.host}:{self.port}")
                
                # Create new SSH client
                self.client = paramiko.SSHClient()
                
                # Load host keys and set policy to auto-accept unknown hosts
                self.client.load_system_host_keys()
                try:
                    self.client.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
                except FileNotFoundError:
                    pass  # known_hosts file doesn't exist yet
                
                # Use WarningPolicy which accepts unknown hosts but logs a warning
                self.client.set_missing_host_key_policy(paramiko.WarningPolicy())
                
                # Connect with key authentication
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    key_filename=str(self.key_path),
                    timeout=30,
                    auth_timeout=30,
                    banner_timeout=30
                )
                
                # Test connection with simple command
                _, stdout, stderr = self.client.exec_command('echo "SSH connection test"')
                if stdout.channel.recv_exit_status() == 0:
                    self.logger.info(f"SSH connection successful to {self.host}")
                    return True
                else:
                    raise SSHConnectionError("SSH test command failed")
                
            except paramiko.AuthenticationException as e:
                # Authentication errors are usually not transient
                self.logger.error(f"SSH authentication failed for {self.username}@{self.host}: {e}")
                raise SSHConnectionError(f"SSH authentication failed: {e}")
                
            except (paramiko.SSHException, OSError, ConnectionError) as e:
                self.logger.warning(f"SSH connection attempt {attempt} failed: {e}")
                
                if self.client:
                    try:
                        self.client.close()
                    except Exception:
                        pass
                    self.client = None
                
                # Wait before retry (except on last attempt)
                if attempt < max_retries:
                    self.logger.info(f"Waiting {retry_delay} seconds before retry...")
                    time.sleep(retry_delay)
                else:
                    raise SSHConnectionError(f"Failed to connect after {max_retries} attempts: {e}")
        
        return False
    
    def execute_command(self, command: str, timeout: int = 300) -> Tuple[int, str, str]:
        """Execute command on remote server.
        
        Args:
            command: Command to execute
            timeout: Command timeout in seconds (default: 300)
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
            
        Raises:
            RemoteOperationError: If command execution fails
        """
        if not self.client:
            raise RemoteOperationError("SSH client not connected")
        
        try:
            self.logger.debug(f"Executing remote command: {command}")
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            
            # Read output
            stdout_data = stdout.read().decode('utf-8', errors='replace')
            stderr_data = stderr.read().decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status()
            
            self.logger.debug(f"Command exit code: {exit_code}")
            
            return exit_code, stdout_data, stderr_data
            
        except Exception as e:
            raise RemoteOperationError(f"Failed to execute command: {e}")
    
    def parse_wp_config(self, wp_config_path: str) -> Dict[str, str]:
        """Parse wp-config.php file for database credentials.
        
        Args:
            wp_config_path: Path to wp-config.php on remote server
            
        Returns:
            Dictionary containing database credentials
            
        Raises:
            RemoteOperationError: If wp-config.php cannot be read or parsed
        """
        # Read wp-config.php file
        command = f"grep 'DB_NAME\\\\|DB_USER\\\\|DB_PASSWORD\\\\|DB_HOST' {wp_config_path}"
        self.logger.debug(f"Executing wp-config parsing command: {command}")
        exit_code, stdout, stderr = self.execute_command(command)
        
        self.logger.debug(f"wp-config grep exit_code: {exit_code}")
        self.logger.debug(f"wp-config grep stdout: {stdout}")
        self.logger.debug(f"wp-config grep stderr: {stderr}")
        
        if exit_code != 0:
            # Try alternative approach - cat the file and grep locally
            cat_command = f"cat {wp_config_path}"
            self.logger.debug(f"Trying alternative: {cat_command}")
            exit_code, stdout, stderr = self.execute_command(cat_command)
            
            if exit_code != 0:
                raise RemoteOperationError(f"Failed to read wp-config.php: {stderr}")
            
            # Filter for database lines locally
            lines = stdout.split('\n')
            config_lines = [line for line in lines if any(db_key in line for db_key in ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST'])]
            config_content = '\n'.join(config_lines)
            self.logger.debug(f"Filtered config content: {config_content}")
        else:
            config_content = stdout
        
        # Parse database configuration using regex
        db_patterns = {
            'DB_NAME': r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            'DB_USER': r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]", 
            'DB_PASSWORD': r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]*)['\"]",
            'DB_HOST': r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]"
        }
        
        db_config = {}
        for key, pattern in db_patterns.items():
            match = re.search(pattern, config_content)
            if match:
                db_config[key.lower()] = match.group(1)
                self.logger.debug(f"Found {key}: {match.group(1)}")
            else:
                self.logger.warning(f"Could not find {key} in wp-config.php")
                self.logger.debug(f"Pattern used: {pattern}")
        
        self.logger.debug(f"Parsed wp-config.php: {db_config}")

        # Validate that we found the essential database parameters
        required_keys = ['db_name', 'db_user', 'db_host']
        missing_keys = [key for key in required_keys if key not in db_config]
        
        if missing_keys:
            raise RemoteOperationError(f"Missing database configuration: {', '.join(missing_keys)}")
        
        # Set default values
        db_config.setdefault('db_password', '')
        
        self.logger.info(f"Parsed database config: host={db_config.get('db_host')}, name={db_config.get('db_name')}, user={db_config.get('db_user')}")
        
        return db_config
    
    def execute_mysqldump(self, db_config: Dict[str, str], output_file: str, temp_dir: str) -> bool:
        """Execute mysqldump and download result.
        
        Args:
            db_config: Database configuration dictionary
            output_file: Local path for the database dump
            temp_dir: Temporary directory on local system
            
        Returns:
            True if mysqldump successful, False otherwise
            
        Raises:
            RemoteOperationError: If mysqldump fails
        """
        # Create remote temporary file for the dump
        remote_dump_file = f"/tmp/wp_backup_{int(time.time())}.sql"
        
        try:
            # Build mysqldump command with proper options
            mysqldump_cmd = self._build_mysqldump_command(db_config, remote_dump_file)
            
            self.logger.info(f"Creating database dump: {db_config['db_name']}")
            self.logger.debug(f"Mysqldump command: {mysqldump_cmd}")
            
            # Execute mysqldump with detailed logging
            exit_code, stdout, stderr = self.execute_command(mysqldump_cmd, timeout=600)
            
            self.logger.debug(f"Mysqldump exit code: {exit_code}")
            self.logger.debug(f"Mysqldump stdout: {stdout}")
            self.logger.debug(f"Mysqldump stderr: {stderr}")
            
            if exit_code != 0:
                self.logger.error(f"Mysqldump failed with exit code {exit_code}")
                self.logger.error(f"Mysqldump stderr: {stderr}")
                self.logger.error(f"Mysqldump stdout: {stdout}")
                raise RemoteOperationError(f"mysqldump failed (exit {exit_code}): {stderr}")
            
            # Verify dump file was created and has content
            check_cmd = f"ls -la {remote_dump_file}"
            exit_code, stdout, stderr = self.execute_command(check_cmd)
            
            if exit_code != 0:
                self.logger.error(f"Dump file not found: {stderr}")
                raise RemoteOperationError(f"Database dump file not created: {stderr}")
            
            self.logger.debug(f"Dump file info: {stdout}")
            
            # Check file size and content
            size_check = stdout.strip().split()
            if len(size_check) >= 5:
                file_size = size_check[4]
                self.logger.debug(f"Dump file size: {file_size} bytes")
                
                if file_size == "0":
                    # File is empty - this is the problem!
                    head_cmd = f"head -n 5 {remote_dump_file}"
                    _, head_out, _ = self.execute_command(head_cmd)
                    self.logger.error(f"Empty dump file content: '{head_out}'")
                    raise RemoteOperationError("Database dump file is empty")
                else:
                    # File has content, let's see what's in it to debug the verification issue
                    head_cmd = f"head -n 20 {remote_dump_file}"
                    _, head_out, _ = self.execute_command(head_cmd)
                    self.logger.debug("Dump file preview (first 20 lines):")
                    self.logger.debug(f"{head_out}")
                    
                    # Specifically check for MySQL dump header
                    if "-- MySQL dump" not in head_out:
                        self.logger.error("Dump file missing MySQL header. Content starts with:")
                        self.logger.error(f"{head_out[:200]}...")
            else:
                # Fallback check
                if "0 " in stdout:  # File size is 0
                    raise RemoteOperationError("Database dump file is empty")
            
            # Download the dump file using sftp
            if not self.sftp:
                self.sftp = self.client.open_sftp()
            
            self.logger.info(f"Downloading database dump to {output_file}")
            self.sftp.get(remote_dump_file, output_file)
            
            # Cleanup remote temporary file
            cleanup_cmd = f"rm -f {remote_dump_file}"
            self.execute_command(cleanup_cmd)
            
            # Verify local file
            if not Path(output_file).exists() or Path(output_file).stat().st_size == 0:
                raise RemoteOperationError("Downloaded dump file is missing or empty")
            
            self.logger.info(f"Database dump completed: {output_file}")
            return True
            
        except Exception as e:
            # Cleanup remote file on error
            try:
                cleanup_cmd = f"rm -f {remote_dump_file}"
                self.execute_command(cleanup_cmd)
            except Exception:
                pass
            
            raise RemoteOperationError(f"Database dump failed: {e}")
    
    def _build_mysqldump_command(self, db_config: Dict[str, str], output_file: str) -> str:
        """Build mysqldump command with proper options.
        
        Args:
            db_config: Database configuration dictionary
            output_file: Remote output file path
            
        Returns:
            Complete mysqldump command string
        """
        base_cmd = "mysqldump"
        
        # Essential options for WordPress databases
        options = [
            "--single-transaction",      # InnoDB consistency
            "--routines",               # Include stored procedures
            "--triggers",               # Include triggers  
            "--complete-insert",        # Full INSERT statements
            "--extended-insert",        # Multiple rows per INSERT
            "--lock-tables=false",      # Don't lock tables
            "--add-drop-table",         # Add DROP TABLE statements
            "--disable-keys",           # Disable key checks
            "--set-charset"             # Set charset info
        ]
        
        # Connection parameters
        host_param = f"--host={db_config['db_host']}"
        user_param = f"--user={db_config['db_user']}"
        
        # Handle password (might be empty)
        password_param = ""
        if db_config.get('db_password'):
            # Use --password parameter directly - safer than MYSQL_PWD in some environments
            password_param = f"--password='{db_config['db_password']}'"
        
        # Build complete command parts
        cmd_parts = [base_cmd] + options + [host_param, user_param]
        if password_param:
            cmd_parts.append(password_param)
        cmd_parts.append(db_config['db_name'])
        
        # Build final command with output redirection
        command = f"{' '.join(cmd_parts)} > {output_file}"
        
        return command
    
    def execute_rsync(self, remote_path: str, local_path: str, 
                     exclude_patterns: List[str] = None, 
                     is_first_backup: bool = False) -> bool:
        """Execute rsync file synchronization.
        
        Args:
            remote_path: Remote directory path to backup
            local_path: Local directory path for backup
            exclude_patterns: List of rsync exclude patterns
            is_first_backup: Whether this is the first backup (full sync)
            
        Returns:
            True if rsync successful, False otherwise
            
        Raises:
            RemoteOperationError: If rsync fails
        """
        # Create local directory if it doesn't exist
        Path(local_path).mkdir(parents=True, exist_ok=True)
        
        # Build rsync command
        rsync_cmd = self._build_rsync_command(remote_path, local_path, exclude_patterns, is_first_backup)
        
        try:
            self.logger.info(f"Starting file synchronization: {remote_path} -> {local_path}")
            self.logger.debug(f"Rsync command: {rsync_cmd}")
            
            # Execute rsync using subprocess (more reliable than SSH exec for large transfers)
            result = subprocess.run(
                rsync_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            if result.returncode == 0:
                self.logger.info("File synchronization completed successfully")
                if result.stdout:
                    self.logger.debug(f"Rsync output: {result.stdout}")
                return True
            else:
                error_msg = f"Rsync failed (exit code {result.returncode}): {result.stderr}"
                self.logger.error(error_msg)
                raise RemoteOperationError(error_msg)
                
        except subprocess.TimeoutExpired:
            raise RemoteOperationError("Rsync operation timed out after 1 hour")
        except Exception as e:
            raise RemoteOperationError(f"Rsync execution failed: {e}")
    
    def _build_rsync_command(self, remote_path: str, local_path: str, 
                            exclude_patterns: List[str] = None,
                            is_first_backup: bool = False) -> str:
        """Build rsync command optimized for incremental backups.
        
        Args:
            remote_path: Remote directory path
            local_path: Local directory path
            exclude_patterns: List of exclude patterns
            is_first_backup: Whether this is first backup
            
        Returns:
            Complete rsync command string
        """
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
                "--update",      # Skip files newer on destination
                "--existing"     # Only update files that exist in dest
            ])
        
        # Add exclusion patterns
        exclude_options = []
        if exclude_patterns:
            for pattern in exclude_patterns:
                exclude_options.append(f"--exclude={pattern}")
        
        # Standard WordPress exclusions
        exclude_options.extend([
            "--exclude=*.log",
            "--exclude=wp-content/cache/",
            "--exclude=wp-content/backup*/",
            "--exclude=.tmp",
            "--exclude=.DS_Store"
        ])
        
        # SSH options for secure connection
        ssh_opts = [
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=~/.ssh/known_hosts",
            "-o", "ConnectTimeout=30",
            "-i", f"{self.key_path}"
        ]
        
        ssh_command = f"ssh {' '.join(ssh_opts)}"
        
        # Build complete rsync command
        # Ensure remote path ends with / for directory sync
        if not remote_path.endswith('/'):
            remote_path += '/'
        if not local_path.endswith('/'):
            local_path += '/'
        
        rsync_cmd_parts = [
            "rsync",
            ' '.join(base_options),
            ' '.join(exclude_options),
            f"-e '{ssh_command}'",
            f"{self.username}@{self.host}:{remote_path}",
            local_path
        ]
        
        return ' '.join(rsync_cmd_parts)
    
    def test_connection(self) -> bool:
        """Test SSH connection and basic functionality.
        
        Returns:
            True if connection test passes, False otherwise
        """
        try:
            if not self.client:
                if not self.connect_with_retry():
                    return False
            
            # Test basic command execution
            exit_code, stdout, stderr = self.execute_command('whoami')
            if exit_code == 0 and stdout.strip() == self.username:
                self.logger.info("SSH connection test passed")
                return True
            else:
                self.logger.error(f"SSH connection test failed: expected user {self.username}, got {stdout.strip()}")
                return False
                
        except Exception as e:
            self.logger.error(f"SSH connection test failed: {e}")
            return False
    
    def close(self):
        """Close SSH and SFTP connections."""
        if self.sftp:
            try:
                self.sftp.close()
            except Exception:
                pass
            self.sftp = None
        
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
        
        self.logger.debug(f"SSH connection closed for {self.host}")
    
    def __enter__(self):
        """Context manager entry."""
        self.connect_with_retry()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()