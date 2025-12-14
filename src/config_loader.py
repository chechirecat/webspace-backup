"""
WordPress Backup Tool Configuration Loader

Handles loading and validation of backup configuration from JSON files.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

class ConfigurationError(Exception):
    """Configuration related errors."""
    pass

class ConfigLoader:
    """Simple configuration file loader and validator."""
    
    def __init__(self, config_path: str):
        """Initialize ConfigLoader with path to configuration file.
        
        Args:
            config_path: Path to the JSON configuration file
        """
        self.config_path = Path(config_path).expanduser()
        self.config = None
        self.logger = logging.getLogger(__name__)
    
    def load_config(self) -> Dict:
        """Load and validate configuration file.
        
        Returns:
            Dictionary containing validated configuration
            
        Raises:
            ConfigurationError: If configuration file is invalid or missing
        """
        if not self.config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")
        
        try:
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in config file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error reading config file: {e}")
        
        # Validate configuration
        if not self.validate_config(self.config):
            raise ConfigurationError("Configuration validation failed")
        
        # Expand paths and apply defaults
        self._process_config()
        
        return self.config
    
    def validate_config(self, config: Dict) -> bool:
        """Validate configuration schema and required fields.
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            True if configuration is valid, False otherwise
        """
        # Check required top-level fields
        required_fields = ['backup_dir', 'sites']
        for field in required_fields:
            if field not in config:
                self.logger.error(f"Missing required field: {field}")
                return False
        
        # Validate sites array
        if not isinstance(config['sites'], list) or len(config['sites']) == 0:
            self.logger.error("'sites' must be a non-empty list")
            return False
        
        # Validate each site configuration
        for i, site in enumerate(config['sites']):
            if not self._validate_site_config(site, i):
                return False
        
        # Validate optional fields
        if 'retention_days' in config:
            if not isinstance(config['retention_days'], int) or config['retention_days'] < 1:
                self.logger.error("'retention_days' must be a positive integer")
                return False
        
        if 'log_level' in config:
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if config['log_level'] not in valid_levels:
                self.logger.error(f"'log_level' must be one of: {valid_levels}")
                return False
        
        return True
    
    def _validate_site_config(self, site: Dict, index: int) -> bool:
        """Validate individual site configuration.
        
        Args:
            site: Site configuration dictionary
            index: Index of site in sites array (for error reporting)
            
        Returns:
            True if site config is valid, False otherwise
        """
        # Required site fields
        required_fields = ['name', 'ssh_host', 'ssh_user', 'ssh_key', 'web_root']
        for field in required_fields:
            if field not in site:
                self.logger.error(f"Site {index}: Missing required field '{field}'")
                return False
            if not isinstance(site[field], str) or not site[field].strip():
                self.logger.error(f"Site {index}: Field '{field}' must be a non-empty string")
                return False
        
        # Validate site name (used in filenames, must be filesystem-safe)
        name = site['name']
        if not name.replace('-', '').replace('_', '').replace('.', '').isalnum():
            self.logger.error(f"Site {index}: Name '{name}' contains invalid characters. Use only letters, numbers, hyphens, underscores, and dots.")
            return False
        
        # Validate optional numeric fields
        if 'ssh_port' in site:
            if not isinstance(site['ssh_port'], int) or site['ssh_port'] < 1 or site['ssh_port'] > 65535:
                self.logger.error(f"Site {index}: 'ssh_port' must be an integer between 1 and 65535")
                return False
        
        if 'retention_days' in site:
            if not isinstance(site['retention_days'], int) or site['retention_days'] < 1:
                self.logger.error(f"Site {index}: 'retention_days' must be a positive integer")
                return False
        
        # Validate exclude patterns if present
        if 'exclude_patterns' in site:
            if not isinstance(site['exclude_patterns'], list):
                self.logger.error(f"Site {index}: 'exclude_patterns' must be a list")
                return False
            for pattern in site['exclude_patterns']:
                if not isinstance(pattern, str):
                    self.logger.error(f"Site {index}: All exclude patterns must be strings")
                    return False
        
        return True
    
    def _process_config(self):
        """Apply defaults and expand paths in configuration."""
        # Set global defaults
        self.config.setdefault('retention_days', 30)
        self.config.setdefault('log_level', 'INFO')
        self.config.setdefault('log_file', '/var/log/wp-backup.log')
        
        # Expand backup directory path
        self.config['backup_dir'] = str(Path(self.config['backup_dir']).expanduser().resolve())
        
        # Expand log file path
        self.config['log_file'] = str(Path(self.config['log_file']).expanduser().resolve())
        
        # Process each site
        for site in self.config['sites']:
            # Set site defaults
            site.setdefault('ssh_port', 22)
            site.setdefault('description', '')
            site.setdefault('exclude_patterns', [])
            site.setdefault('retention_days', self.config['retention_days'])
            
            # Set wp_config_path default if not provided
            if 'wp_config_path' not in site:
                site['wp_config_path'] = f"{site['web_root']}/wp-config.php"
            
            # Expand SSH key path
            site['ssh_key'] = str(Path(site['ssh_key']).expanduser().resolve())
    
    def get_sites(self) -> List[Dict]:
        """Return list of configured WordPress sites.
        
        Returns:
            List of site configuration dictionaries
            
        Raises:
            ConfigurationError: If configuration hasn't been loaded yet
        """
        if self.config is None:
            raise ConfigurationError("Configuration not loaded. Call load_config() first.")
        
        return self.config['sites']
    
    def get_site_by_name(self, name: str) -> Optional[Dict]:
        """Get site configuration by name.
        
        Args:
            name: Site name to search for
            
        Returns:
            Site configuration dictionary or None if not found
        """
        if self.config is None:
            return None
        
        for site in self.config['sites']:
            if site['name'] == name:
                return site
        
        return None
    
    def get_backup_dir(self) -> str:
        """Get the backup directory path.
        
        Returns:
            Absolute path to backup directory
            
        Raises:
            ConfigurationError: If configuration hasn't been loaded yet
        """
        if self.config is None:
            raise ConfigurationError("Configuration not loaded. Call load_config() first.")
        
        return self.config['backup_dir']
    
    def get_global_settings(self) -> Dict:
        """Return global configuration settings.
        
        Returns:
            Dictionary containing global settings
            
        Raises:
            ConfigurationError: If configuration hasn't been loaded yet
        """
        if self.config is None:
            raise ConfigurationError("Configuration not loaded. Call load_config() first.")
        
        return {
            'backup_dir': self.config['backup_dir'],
            'retention_days': self.config['retention_days'],
            'log_level': self.config['log_level'],
            'log_file': self.config['log_file']
        }