# System Architecture

## Overview

The WordPress Multi-Instance Backup Tool follows a modular architecture with clear separation of concerns. The system operates from a Linux host and connects to remote WordPress instances via SSH to perform automated backups.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Linux Host (or WSL)                     │
│                                                             │
│ ┌─────────────────────────────────────────────────────────┐│
│ │              Backup Controller                          ││
│ │            (Orchestrates Process)                       ││
│ └─────────────────────────────────────────────────────────┘│
│                                                             │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│ │ Config      │  │ SSH Client  │  │ Backup      │          │
│ │ Loader      │  │ (All Remote │  │ Storage     │          │
│ │             │  │ Operations) │  │ (Archives)  │          │
│ └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ SSH/SFTP
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Remote WordPress Instances                 │
│                                                             │
│ ┌─────────────────┐  ┌─────────────────┐  ┌───────────────┐│
│ │   Instance #1   │  │   Instance #2   │  │ Instance #N   ││
│ │                 │  │                 │  │               ││
│ │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌───────────┐ ││
│ │ │ Web Files   │ │  │ │ Web Files   │ │  │ │Web Files  │ ││
│ │ │             │ │  │ │             │ │  │ │           │ ││
│ │ │wp-config.php│ │  │ │wp-config.php│ │  │ │wp-config  │ ││
│ │ └─────────────┘ │  │ └─────────────┘ │  │ └───────────┘ ││
│ │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌───────────┐ ││
│ │ │  MariaDB    │ │  │ │  MariaDB    │ │  │ │ MariaDB   │ ││
│ │ │             │ │  │ │             │ │  │ │           │ ││
│ │ └─────────────┘ │  │ └─────────────┘ │  │ └───────────┘ ││
│ └─────────────────┘  └─────────────────┘  └───────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Component Architecture

### Core Components

#### 1. Backup Controller
- **Purpose**: Orchestrates the entire backup workflow
- **Responsibilities**:
  - Load and validate configuration
  - Iterate through configured WordPress sites
  - Coordinate backup operations with error recovery
  - Generate backup summary reports
  - Manage overall logging and monitoring

#### 2. Config Loader
- **Purpose**: Simple configuration management
- **Responsibilities**:
  - Parse JSON configuration file
  - Validate required fields and formats
  - Provide site configurations to controller
  - Handle configuration security (file permissions)

#### 3. SSH Client
- **Purpose**: Handle all remote operations via SSH
- **Responsibilities**:
  - Establish and manage SSH connections
  - Execute mysqldump commands remotely
  - Execute rsync for file synchronization
  - Parse wp-config.php files remotely
  - Handle SSH authentication and connection errors
  - Implement retry logic for network failures

#### 4. Backup Storage
- **Purpose**: Local backup file management
- **Responsibilities**:
  - Create timestamped compressed archives
  - Manage separate database and file archives
  - Implement retention policy (cleanup old backups)
  - Verify backup integrity with checksums
  - Handle local file system operations

## Data Flow

### Simplified Backup Workflow
```
Config File → Config Loader → Controller → For Each Site:
    ├── SSH Client: Parse wp-config.php
    ├── SSH Client: Execute mysqldump → Backup Storage: DB Archive
    ├── SSH Client: Execute rsync → Backup Storage: Files Archive
    └── Backup Storage: Verify + Cleanup Old Backups
```

### Detailed Operation Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│Load Config  │───▶│ For Each    │───▶│ Connect SSH │
│& Validate   │    │ Site        │    │ (5 retries) │
└─────────────┘    └─────────────┘    └─────────────┘
                                             │
                                             ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│Create DB    │◀───│ Compress &  │◀───│ Execute     │
│Archive +    │    │ Verify      │    │ mysqldump   │
│Checksum     │    │ Checksums   │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                                             │
                                             ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│Create Files │◀───│ Compress &  │◀───│ Execute     │
│Archive +    │    │ Verify      │    │ rsync       │
│Checksum     │    │ Checksums   │    │ --update    │
└─────────────┘    └─────────────┘    └─────────────┘
                                             │
                                             ▼
                          ┌─────────────────────────────┐
                          │ Cleanup Old Backups        │
                          │ (Retention Policy)          │
                          └─────────────────────────────┘
```

## Security Architecture

### Authentication Layer
- SSH key-based authentication only
- Per-instance SSH key configuration
- Secure key storage and access controls

### Network Security
- Encrypted SSH/SFTP connections
- Connection timeout configurations
- Host key verification

### File System Security
- Secure temporary file handling
- Restricted configuration file permissions
- Safe archive storage locations

## Scalability Considerations

### Horizontal Scaling
- Independent instance processing
- Parallel backup operations (future enhancement)
- Distributed backup storage options

### Performance Optimization
- Incremental backup strategies
- Compression optimization
- Network bandwidth management

## Error Handling Strategy

### Error Classification and Response

#### Fatal Errors (Abort Completely)
- Configuration file missing or invalid JSON syntax
- SSH private key file missing or invalid permissions
- Backup storage directory not writable

#### Recoverable Errors (Log + Continue to Next Site)
- SSH authentication failure for specific site
- wp-config.php file not found or unreadable
- mysqldump command failure (database access issues)
- rsync failure (permission or disk space issues)

#### Transient Errors (Retry with Backoff)
- SSH connection timeouts or network issues
- Temporary file system errors
- **Retry Strategy**: 5 attempts with 5-second intervals

### Backup Verification (Full Checksum Validation)
- **Database Archives**: Validate gzip integrity + SQL syntax check
- **File Archives**: Verify tar.gz integrity + file count comparison
- **Checksums**: Generate and store SHA256 checksums for all archives
- **Failed Verification**: Log error, mark backup as incomplete, continue to next site

### Recovery Procedures
- Detailed per-site backup status in logs
- Failed backups clearly marked with error codes
- Checksum files enable integrity verification
- Manual re-run possible for individual sites