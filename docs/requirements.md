# Requirements Specification

## Functional Requirements

### FR-001: Multi-Instance Backup Support
- **Description**: System must support backup of multiple WordPress installations
- **Details**: Each instance may be on different domains, hosting accounts, and servers
- **Priority**: High
- **Acceptance Criteria**: 
  - Configuration file supports multiple instance definitions
  - Backup process can handle all configured instances in sequence
  - Each instance can be backed up independently

### FR-002: Database Backup
- **Description**: System must create full MySQL/MariaDB database dumps
- **Details**: Extract database credentials from wp-config.php and perform complete backup
- **Priority**: High
- **Acceptance Criteria**:
  - Automatic parsing of wp-config.php for database credentials
  - Full database dump using mysqldump
  - Compressed storage of database backups
  - Timestamped naming convention

### FR-003: File Backup
- **Description**: System must backup WordPress files with incremental synchronization
- **Details**: Use rsync for efficient incremental backups of web files
- **Priority**: High
- **Acceptance Criteria**:
  - Incremental backup as default mode
  - Option to force full backup
  - Preserve file permissions and timestamps
  - Handle large media files efficiently

### FR-004: SSH/SFTP Access
- **Description**: System must connect to remote servers via SSH
- **Details**: Use SSH key authentication for secure access
- **Priority**: High
- **Acceptance Criteria**:
  - SSH key-based authentication only
  - Support for different SSH users per instance
  - Secure file transfers via SFTP
  - Connection timeout handling

### FR-005: Configuration Management
- **Description**: System must use external configuration file
- **Details**: JSON configuration defining all WordPress instances and settings
- **Priority**: High
- **Acceptance Criteria**:
  - Single configuration file for all instances
  - Validation of configuration syntax
  - Support for backup retention policies
  - Configurable storage locations

### FR-006: Archive Management
- **Description**: System must create compressed timestamped archives
- **Details**: Organize backups with human-readable timestamps
- **Priority**: Medium
- **Acceptance Criteria**:
  - YYYY-MM-DD_HH-MM-SS naming format
  - Compressed storage (gzip/zip)
  - Separate or combined archives for DB and files
  - Configurable retention periods

## Non-Functional Requirements

### NFR-001: Platform Compatibility
- **Description**: Must run on Linux host systems
- **Target**: Ubuntu 20.04+, CentOS 8+, Debian 11+
- **Priority**: High

### NFR-002: Authentication Security
- **Description**: SSH key-based authentication only
- **Details**: No password authentication support
- **Priority**: High

### NFR-003: Performance
- **Description**: Efficient handling of large file sets
- **Details**: Incremental backups to minimize transfer time
- **Priority**: Medium

### NFR-004: Reliability
- **Description**: Robust error handling and recovery
- **Details**: Continue processing other instances if one fails
- **Priority**: Medium

### NFR-005: Maintainability
- **Description**: Modular code structure for easy maintenance
- **Details**: Clear separation of concerns, comprehensive logging
- **Priority**: Medium

## Constraints

### C-001: Network Dependencies
- SSH connectivity to all target WordPress instances required
- Reliable internet connection for remote operations

### C-002: Permission Requirements
- SSH access with sufficient privileges for file access and database operations
- Read access to wp-config.php files

### C-003: Storage Requirements
- Sufficient local storage for backup archives
- Write permissions to backup destination directories

## Assumptions

### A-001: WordPress Structure
- Standard WordPress directory structure
- wp-config.php in predictable location
- Standard database table prefix (customizable)

### A-002: Remote Environment
- mysqldump utility available on remote servers
- rsync compatibility on remote systems
- SSH daemon properly configured

### A-003: Security Model
- SSH keys properly distributed and configured
- Firewall rules allow SSH connections
- Database access from SSH connection context