# WordPress Multi-Instance Backup Tool

A Python-based solution for automated backup of multiple WordPress installations across different hosting accounts using SSH connections.

## Purpose

This tool provides automated backup capabilities for WordPress installations hosted on remote servers. It supports:
- Multiple WordPress instances across different domains and hosting accounts
- Database dumps with timestamped archives
- Incremental file synchronization using rsync
- SSH key-based authentication for secure remote access
- Configuration-driven backup management

## Usage

### Installation
```bash
# Install Python dependencies
pip install -r requirements.txt

# Make script executable (Linux/WSL)
chmod +x wp-backup.py
```

### Basic Commands
```bash
# Validate configuration file
python wp-backup.py --validate

# Test connections without backing up
python wp-backup.py --dry-run

# Backup all configured sites
python wp-backup.py

# Backup specific site only
python wp-backup.py --site example-com

# Show backup statistics
python wp-backup.py --summary

# Use custom configuration file
python wp-backup.py --config /path/to/custom-config.json

# Verbose output for debugging
python wp-backup.py --verbose
```

### Configuration
Edit `config.json` with your WordPress site details:

```json
{
  "backup_dir": "/opt/wp-backups",
  "retention_days": 30,
  "log_level": "INFO",
  "log_file": "/var/log/wp-backup.log",
  "sites": [
    {
      "name": "your-site",
      "description": "Your WordPress site",
      "ssh_host": "your-server.com",
      "ssh_user": "username",
      "ssh_key": "~/.ssh/wp-backup-key",
      "web_root": "/var/www/html",
      "exclude_patterns": ["*.log", "wp-content/cache/*"]
    }
  ]
}
```

## Preparation

### Prerequisites
- Linux host system or Windows with WSL
- Python 3.8+ installed
- SSH access to WordPress hosting accounts
- SSH private keys for authentication
- Required system utilities: `rsync`, `ssh`, `mysqldump` (on remote servers)

### Installation Steps

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd wp-backup
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Generate SSH key for backups**
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/wp-backup-key -C "wp-backup-tool"
   ```

4. **Copy SSH key to your WordPress servers**
   ```bash
   ssh-copy-id -i ~/.ssh/wp-backup-key.pub user@your-server.com
   ```

5. **Set proper SSH key permissions**
   ```bash
   chmod 600 ~/.ssh/wp-backup-key
   chmod 644 ~/.ssh/wp-backup-key.pub
   ```

6. **Configure your sites**
   - Edit `config.json` with your WordPress site details
   - Update SSH hosts, usernames, and paths
   - Set backup directory and retention policies

7. **Test configuration**
   ```bash
   python wp-backup.py --validate
   python wp-backup.py --dry-run
   ```

## Contributing

### Development Setup

1. **Set up development environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/WSL
   # or
   venv\Scripts\activate     # Windows
   
   pip install -r requirements.txt
   ```

2. **Project structure**
   ```
   wp-backup/
   ├── src/                 # Core modules
   │   ├── config_loader.py    # Configuration management
   │   ├── ssh_client.py       # SSH operations
   │   ├── backup_storage.py   # Archive & verification
   │   └── backup_controller.py # Main orchestrator
   ├── docs/               # Documentation
   ├── wp-backup.py        # CLI entry point
   └── config.json         # Configuration file
   ```

3. **Testing changes**
   ```bash
   # Validate configuration
   python wp-backup.py --validate
   
   # Test connections
   python wp-backup.py --dry-run
   
   # Run with verbose logging
   python wp-backup.py --verbose
   ```

### Code Standards
- Python 3.8+ compatibility
- Type hints for function parameters and returns
- Comprehensive error handling and logging
- Modular design with clear separation of concerns
- WSL compatibility for Windows users

---

## Documentation

For detailed technical information, see the documentation in the `/docs` folder:

- [Requirements](docs/requirements.md) - Functional and non-functional requirements
- [Architecture](docs/architecture.md) - System design and component overview
- [Technical Details](docs/technical-details.md) - Implementation specifics and technology stack