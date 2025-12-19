#!/usr/bin/env python3
"""
WordPress Multi-Instance Backup Tool

Command-line interface for backing up multiple WordPress installations.
"""

import argparse
import sys
import logging
from pathlib import Path
from src.backup_controller import BackupController, BackupError
from src.config_loader import ConfigurationError


def main():
    """Main entry point for the WordPress backup tool."""
    parser = argparse.ArgumentParser(
        description="WordPress Multi-Instance Backup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                            # Backup all configured sites
  %(prog)s --site example-com         # Backup specific site
  %(prog)s --dry-run                  # Test configuration and connections
  %(prog)s --config /path/config.json # Use custom config file
  %(prog)s --summary                  # Show backup statistics
        """
    )
    
    # Configuration
    parser.add_argument(
        '--config', '-c',
        default='config.json',
        help='Path to configuration file (default: config.json)'
    )
    
    # Backup options
    parser.add_argument(
        '--site', '-s',
        help='Backup specific site only (by name)'
    )
    
    parser.add_argument(
        '--dry-run', '-n',
        action='store_true',
        help='Test configuration and connections without performing backup'
    )
    
    parser.add_argument(
        '--summary',
        action='store_true', 
        help='Show backup statistics and exit'
    )
    
    # Validation
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Validate configuration file and exit'
    )
    
    # Verbosity
    parser.add_argument(
        '--verbose', '-v',
        action='count',
        default=0,
        help='Increase verbosity (use -v, -vv, or -vvv)'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress output except errors'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate config file exists
    config_file = Path(args.config)
    if not config_file.exists():
        print(f"Error: Configuration file not found: {config_file}", file=sys.stderr)
        print("Create a configuration file or use --config to specify a different path.", file=sys.stderr)
        return 1
    
    try:
        controller = BackupController(str(config_file), args.verbose)
        
        # Handle different operation modes
        if args.validate:
            return handle_validate(controller)
        elif args.summary:
            return handle_summary(controller, args.site)
        else:
            return handle_backup(controller, args)
            
    except ConfigurationError as e:
        print(f"Configuration Error: {e}", file=sys.stderr)
        return 1
    except BackupError as e:
        print(f"Backup Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\\nOperation cancelled by user", file=sys.stderr)
        return 130  # Standard exit code for SIGINT
    except Exception as e:
        print(f"Unexpected Error: {e}", file=sys.stderr)
        return 1


def handle_validate(controller: BackupController) -> int:
    """Handle configuration validation.
    
    Args:
        controller: BackupController instance
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    print("Validating configuration...")
    
    try:
        is_valid, errors = controller.validate_configuration()
        
        if is_valid:
            print("✓ Configuration validation passed")
            return 0
        else:
            print("✗ Configuration validation failed:")
            for error in errors:
                print(f"  - {error}")
            return 1
            
    except Exception as e:
        print(f"Validation failed: {e}", file=sys.stderr)
        return 1


def handle_summary(controller: BackupController, site_name: str = None) -> int:
    """Handle backup summary display.
    
    Args:
        controller: BackupController instance
        site_name: Optional site name to filter by
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        summary = controller.get_backup_summary(site_name)
        
        print("Backup Summary")
        print("=" * 50)
        
        if summary['total_sites'] == 0:
            print("No backups found.")
            return 0
        
        print(f"Total sites: {summary['total_sites']}")
        print(f"Total backups: {summary['total_backups']}")
        print(f"Total size: {format_bytes(summary['total_size_bytes'])}")
        print()
        
        for site, info in summary['sites'].items():
            print(f"Site: {site}")
            print(f"  Backups: {info['backup_count']}")
            print(f"  Size: {format_bytes(info['total_size_bytes'])}")
            if info['latest_backup']:
                print(f"  Latest: {info['latest_backup']}")
            print()
        
        return 0
        
    except Exception as e:
        print(f"Failed to generate summary: {e}", file=sys.stderr)
        return 1


def handle_backup(controller: BackupController, args) -> int:
    """Handle backup operations.
    
    Args:
        controller: BackupController instance
        args: Parsed command line arguments
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        # Configure verbosity based on arguments
        if args.quiet:
            # Suppress all output except errors
            logging.getLogger().setLevel(logging.ERROR)
        elif args.verbose >= 2:
            # Very verbose - set DEBUG level
            logging.getLogger().setLevel(logging.DEBUG)
            logging.getLogger('paramiko').setLevel(logging.WARNING)  # Reduce paramiko noise
        elif args.verbose >= 1:
            # Verbose - set INFO level (already default but ensure it)
            logging.getLogger().setLevel(logging.INFO)
        
        # Run backup
        success = controller.run_backup(
            site_filter=args.site,
            dry_run=args.dry_run
        )
        
        return 0 if success else 1
        
    except Exception as e:
        print(f"Backup operation failed: {e}", file=sys.stderr)
        return 1


def format_bytes(bytes_value: int) -> str:
    """Format byte value in human-readable format.
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.2 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def check_dependencies():
    """Check if required system dependencies are available."""
    import shutil
    
    required_commands = ['rsync', 'ssh']
    missing = []
    
    for cmd in required_commands:
        if not shutil.which(cmd):
            missing.append(cmd)
    
    if missing:
        print(f"Error: Required system commands not found: {', '.join(missing)}", file=sys.stderr)
        print("Please install the missing dependencies and try again.", file=sys.stderr)
        return False
    
    return True


if __name__ == '__main__':
    # Check system dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Run main program
    exit_code = main()
    sys.exit(exit_code)
