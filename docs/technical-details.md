# Technical Implementation Details

## Technology Stack

### Core Technologies
- **Language**: Python 3.8+
- **SSH/SFTP Library**: Paramiko or Fabric
- **File Synchronization**: rsync (system utility)
- **Compression**: Built-in tarfile/gzipfile modules
- **Configuration**: JSON with optional YAML support
- **Logging**: Python logging module with file and console handlers

### Required Python Packages
```
paramiko>=2.7.0          # SSH client library
pyyaml>=5.4.0           # YAML configuration support (optional)
cryptography>=3.4.0     # SSH key handling
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

### Main Configuration File (config.json)
```json
{
  "global": {
    "backup_root": "/opt/wp-backups",
    "log_level": "INFO",
    "log_file": "/var/log/wp-backup.log",
    "retention_days": 30,
    "compression": "gzip",
    "parallel_instances": false
  },
  "defaults": {
    "ssh_port": 22,
    "ssh_timeout": 30,
    "backup_mode": "incremental",
    "include_uploads": true,
    "exclude_cache": true
  },
  "instances": [
    {
      "name": "example-com",
      "description": "Main company website",
      "ssh": {
        "host": "server1.provider.com",
        "port": 22,
        "username": "user1",
        "private_key_path": "~/.ssh/wp-backup-key",
        "host_key_policy": "strict"
      },
      "paths": {
        "web_root": "/var/www/html",
        "wp_config": "/var/www/html/wp-config.php",
        "exclude_patterns": ["*.log", "wp-content/cache/*"]
      },
      "database": {
        "auto_discover": true,
        "manual_override": {
          "host": null,
          "name": null,
          "user": null,
          "password": null
        }
      },
      "backup": {
        "mode": "incremental",
        "schedule": "daily",
        "retention_days": 60
      }
    }
  ]
}
```

### SSH Key Configuration
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

### 1. ConfigManager Class
```python
class ConfigManager:
    """Handle configuration file operations and validation."""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = None
    
    def load_config(self) -> dict:
        """Load and validate configuration file."""
        pass
    
    def validate_config(self, config: dict) -> bool:
        """Validate configuration schema and values."""
        pass
    
    def get_instances(self) -> List[dict]:
        """Return list of configured WordPress instances."""
        pass
    
    def get_global_settings(self) -> dict:
        """Return global configuration settings."""
        pass
```

### 2. SSHConnector Class
```python
class SSHConnector:
    """Handle SSH connections and remote operations."""
    
    def __init__(self, host: str, username: str, key_path: str, port: int = 22):
        self.host = host
        self.username = username
        self.key_path = key_path
        self.port = port
        self.client = None
        self.sftp = None
    
    def connect(self) -> bool:
        """Establish SSH connection."""
        pass
    
    def execute_command(self, command: str) -> tuple:
        """Execute remote command and return output."""
        pass
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file via SFTP."""
        pass
    
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload file via SFTP."""
        pass
    
    def close(self):
        """Close SSH and SFTP connections."""
        pass
```

### 3. DatabaseHandler Class
```python
class DatabaseHandler:
    """Handle database backup operations."""
    
    def __init__(self, ssh_connector: SSHConnector):
        self.ssh = ssh_connector
        self.db_config = None
    
    def parse_wp_config(self, wp_config_path: str) -> dict:
        """Parse wp-config.php for database credentials."""
        pass
    
    def create_dump(self, output_path: str) -> bool:
        """Create database dump using mysqldump."""
        pass
    
    def validate_dump(self, dump_path: str) -> bool:
        """Validate database dump integrity."""
        pass
```

### 4. FileHandler Class
```python
class FileHandler:
    """Handle file synchronization and backup operations."""
    
    def __init__(self, ssh_connector: SSHConnector):
        self.ssh = ssh_connector
    
    def sync_files(self, remote_path: str, local_path: str, mode: str = "incremental") -> bool:
        """Synchronize files using rsync."""
        pass
    
    def build_rsync_command(self, source: str, destination: str, options: dict) -> str:
        """Build rsync command with appropriate options."""
        pass
    
    def validate_sync(self, source: str, destination: str) -> bool:
        """Validate file synchronization results."""
        pass
```

### 5. ArchiveManager Class
```python
class ArchiveManager:
    """Create and manage backup archives."""
    
    def __init__(self, backup_root: str, compression: str = "gzip"):
        self.backup_root = backup_root
        self.compression = compression
    
    def create_archive(self, source_path: str, archive_name: str) -> str:
        """Create compressed archive from source directory."""
        pass
    
    def generate_timestamp(self) -> str:
        """Generate timestamp for archive naming."""
        pass
    
    def cleanup_old_backups(self, instance_name: str, retention_days: int):
        """Remove old backup archives based on retention policy."""
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

## File Synchronization Strategy

### Rsync Configuration
```python
def build_rsync_options(self, mode: str, exclude_patterns: List[str] = None) -> dict:
    """Build rsync options based on backup mode and exclusions."""
    
    base_options = [
        "-a",           # Archive mode (recursive, preserve attributes)
        "-v",           # Verbose output
        "-z",           # Compress during transfer
        "--stats",      # Show transfer statistics
        "--human-readable"  # Human-readable output
    ]
    
    if mode == "incremental":
        base_options.extend([
            "--update",     # Skip files newer on destination
            "--times",      # Preserve modification times
            "--checksum"    # Use checksums for comparison
        ])
    
    if exclude_patterns:
        for pattern in exclude_patterns:
            base_options.append(f"--exclude={pattern}")
    
    return {
        "options": base_options,
        "ssh_options": [
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=~/.ssh/known_hosts"
        ]
    }
```

## Error Handling and Logging

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

## Security Implementation

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