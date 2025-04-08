## SFS - Simple File Sync

This project is a file synchronization utility written in C++ that efficiently syncs files between two directories. It detects changes, resolves conflicts, manages file versions, and supports customizable ignore patterns. Ideal for maintaining consistent backups or syncing data across local directories.

### Quick Start

Compile the program
Dependencies Required: OpenSSL and `nlohmann/json`

```bash
g++ main.cpp -std=c++17 -lcrypto -o sfs.exe
```

Run the sync tool:

```bash
./sfs.exe <source_directory> <destination_directory> <index_file.json> [--dry-run] [--symlinks]
```

- `--dry-run`: Preview changes without modifying files.
- `--symlinks`: Utilize symbolic links for source and destination paths.

## Key Features

<details>
<summary>Click to expand Key Features</summary>

### Directory Scanning
- Recursively scans directories and captures file metadata (modification times and SHA256 hashes) to efficiently manage synchronization.

### Ignore Patterns
- Supports flexible exclusion of files or directories using customizable ignore patterns (`ignore_patterns.txt`).

### File Integrity (SHA256)
- Implements SHA256 hashing to detect and verify file changes accurately.

### Conflict Detection and Resolution
- Automatically detects conflicts during synchronization.
- Handles file renames and resolves conflicts intelligently by preserving conflicting files with clear `.CONFLICT` markers.

### Versioning and Archiving
- Preserves old or deleted files by moving them to a designated `Versions` folder with timestamped backups, allowing easy rollback.

### JSON-based Indexing
- Maintains a lightweight JSON index to track file synchronization states, significantly speeding up subsequent synchronization operations.

### Dry-run Mode
- Provides a safe, simulated synchronization mode (`--dry-run`) to preview changes without altering files.

### Symbolic Links Support
- Offers the ability to create and manage symbolic links, simplifying synchronization across arbitrary locations.

</details>

## TODO's
<details>
<summary>Click to expand future features</summary>

### Enhanced Conflict Resolution
- Implement a more sophisticated merging strategy, particularly for textual files, by integrating a three-way merging algorithms.

### Performance Optimization
- Parallelize file hashing and scanning operations using multithreading.
- Implement caching mechanisms to avoid unnecessary rehashing of large files that haven't changed.

### Logging and Audit Trail
- Integrate structured logging (to file or central logging systems) instead of just standard output.
- Implement verbosity levels (info, debug, error) and log rotation.

### Security and Encryption
- Add file-level encryption to protect sensitive files during synchronization.
- Support secure network-based synchronization through SSL/TLS.

### Real-time Sync Capabilities
- Implement directory watchers for near real-time synchronization without manual triggering.

### Backup and Restore Functionality
- Introduce snapshot management and restore features that can roll back directories to previous versions, complementing your existing versioning strategy.

### Remote Synchronization Support
- Extend it to handle remote file synchronization over protocols such as FTP, SFTP, SMB or cloud storage APIs.

### Enhanced Pattern Matching and Filtering
- Support more advanced wildcard/glob or regex-based file filtering.
- Allow users to dynamically add, edit, or remove ignore patterns via command-line arguments or configuration files.

### User Interface and Reporting
- Develop a GUI for easier monitoring and management.
- Provide summary reports of synchronization tasks, including performance metrics and statistics.
</details>