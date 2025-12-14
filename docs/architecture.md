# System Architecture

## Overview

The WordPress Multi-Instance Backup Tool follows a modular architecture with clear separation of concerns. The system operates from a Linux host and connects to remote WordPress instances via SSH to perform automated backups.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Linux Host                               │
│                                                             │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│ │   Config    │  │   Logger    │  │  Archive    │          │
│ │  Manager    │  │             │  │  Manager    │          │
│ └─────────────┘  └─────────────┘  └─────────────┘          │
│                                                             │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│ │    SSH      │  │  Database   │  │    File     │          │
│ │ Connector   │  │   Handler   │  │  Handler    │          │
│ └─────────────┘  └─────────────┘  └─────────────┘          │
│                                                             │
│ ┌─────────────────────────────────────────────────────────┐│
│ │              Main Backup Controller                     ││
│ └─────────────────────────────────────────────────────────┘│
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

#### 1. Main Backup Controller
- **Purpose**: Orchestrates the entire backup process
- **Responsibilities**:
  - Load and validate configuration
  - Iterate through configured instances
  - Coordinate backup operations
  - Handle global error scenarios
  - Generate summary reports

#### 2. Config Manager
- **Purpose**: Handle configuration file operations
- **Responsibilities**:
  - Parse JSON/YAML configuration files
  - Validate configuration syntax and values
  - Provide configuration data to other components
  - Handle configuration file security

#### 3. SSH Connector
- **Purpose**: Manage SSH connections and remote operations
- **Responsibilities**:
  - Establish SSH connections using key authentication
  - Execute remote commands
  - Handle SFTP file transfers
  - Manage connection lifecycle and cleanup

#### 4. Database Handler
- **Purpose**: Handle database backup operations
- **Responsibilities**:
  - Parse wp-config.php for database credentials
  - Execute remote mysqldump commands
  - Transfer database dumps to local system
  - Validate database backup integrity

#### 5. File Handler
- **Purpose**: Manage file synchronization and backup
- **Responsibilities**:
  - Execute rsync operations for file synchronization
  - Handle incremental and full backup modes
  - Manage file transfer progress and errors
  - Preserve file permissions and timestamps

#### 6. Archive Manager
- **Purpose**: Create and manage backup archives
- **Responsibilities**:
  - Compress backup files into archives
  - Generate timestamped file names
  - Manage backup retention policies
  - Clean up temporary files

#### 7. Logger
- **Purpose**: Centralized logging and monitoring
- **Responsibilities**:
  - Log all operations and errors
  - Generate backup reports
  - Monitor system performance
  - Handle log rotation and retention

## Data Flow

### 1. Initialization Phase
```
Configuration File → Config Manager → Validation → Main Controller
```

### 2. Instance Processing Phase
```
For each WordPress instance:
  SSH Connection → Remote Discovery → Database Backup → File Backup → Archive Creation
```

### 3. Backup Operation Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Establish   │───▶│   Parse     │───▶│  Execute    │
│ SSH Conn    │    │ wp-config   │    │ mysqldump   │
└─────────────┘    └─────────────┘    └─────────────┘
                                             │
                                             ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Create    │◀───│  Transfer   │◀───│  Compress   │
│  Archive    │    │  to Local   │    │    Dump     │
└─────────────┘    └─────────────┘    └─────────────┘
```

### 4. File Synchronization Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Analyze     │───▶│  Execute    │───▶│   Create    │
│ Changes     │    │   rsync     │    │  Archive    │
└─────────────┘    └─────────────┘    └─────────────┘
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

### Fault Tolerance
- Continue processing remaining instances on single failure
- Retry mechanisms for transient network issues
- Graceful degradation for partial failures

### Recovery Procedures
- Detailed error logging and reporting
- Backup verification mechanisms
- Manual recovery documentation