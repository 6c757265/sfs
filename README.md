## Key Features

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
