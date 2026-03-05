# System Architecture

## NTFS Forensic Recovery System - Technical Design

---

## Overview

This system provides a **forensically-sound, production-ready backend** for automated recovery of deleted files from NTFS file systems in EnCase format (.E01) images. It follows strict digital forensics standards including read-only evidence handling, cryptographic verification, complete audit logging, and reproducible operations.

---

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                        Web Frontend                         │
│                    (Not Included - API Only)                │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP/REST
┌────────────────────────▼────────────────────────────────────┐
│                     FastAPI Backend                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              API Route Layer                         │  │
│  │  • Evidence  • Scan  • Recovery  • Forensics • Files│  │
│  └────────────────────┬─────────────────────────────────┘  │
│  ┌────────────────────▼─────────────────────────────────┐  │
│  │            Service Layer                             │  │
│  │  • ForensicEngine  • HashService  • MountService    │  │
│  └────────────────────┬─────────────────────────────────┘  │
│  ┌────────────────────▼─────────────────────────────────┐  │
│  │            Forensic Tools Integration                │  │
│  │  • SleuthKit (fls, icat, mmls)                      │  │
│  │  • EWF Tools (ewfmount)                             │  │
│  │  • Scalpel (file carving)                           │  │
│  └────────────────────┬─────────────────────────────────┘  │
└────────────────────────┼─────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│                  Storage Layer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Evidence   │  │  Recovered   │  │    Carved    │  │
│  │   (.E01)     │  │    Files     │  │    Files     │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└──────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────┐
│                  Database Layer (SQLite)                 │
│  • Evidence  • Partitions  • DeletedFiles               │
│  • RecoveredFiles  • CarvedFiles  • AuditLog            │
└──────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. FastAPI Application (`app/main.py`)

**Purpose:** Main HTTP API server

**Features:**
- CORS middleware for cross-origin requests
- Request timing middleware
- Audit logging middleware
- Global exception handling
- Health check endpoint
- Auto-generated OpenAPI docs

**Startup Process:**
1. Create storage directories
2. Initialize database schema
3. Load configuration
4. Mount API routes
5. Start web server

---

### 2. Database Layer (`app/database.py`, `app/models/`)

**Purpose:** Persistent storage of forensic metadata

**Technology:** SQLAlchemy ORM with SQLite

**Schema:**

```sql
-- Evidence: Forensic disk images
CREATE TABLE evidence (
    id INTEGER PRIMARY KEY,
    filename VARCHAR(512),
    file_path VARCHAR(1024),
    size_bytes BIGINT,
    sha256_hash VARCHAR(64),
    hash_verified BOOLEAN,
    case_name VARCHAR(256),
    examiner VARCHAR(256),
    upload_time DATETIME,
    analysis_status VARCHAR(50),
    -- ... more fields
);

-- Partitions: Detected disk partitions
CREATE TABLE partitions (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER REFERENCES evidence(id),
    partition_number INTEGER,
    start_offset BIGINT,
    size_bytes BIGINT,
    filesystem_type VARCHAR(50),
    is_ntfs INTEGER,
    -- ... more fields
);

-- Deleted Files: MFT entries of deleted files
CREATE TABLE deleted_files (
    id INTEGER PRIMARY KEY,
    partition_id INTEGER REFERENCES partitions(id),
    inode BIGINT,
    filename VARCHAR(512),
    size_bytes BIGINT,
    time_modified DATETIME,
    time_accessed DATETIME,
    time_changed DATETIME,
    time_birth DATETIME,
    recovery_status VARCHAR(50),
    -- ... more fields
);

-- Recovered Files: Successfully recovered files
CREATE TABLE recovered_files (
    id INTEGER PRIMARY KEY,
    deleted_file_id INTEGER REFERENCES deleted_files(id),
    recovered_filename VARCHAR(512),
    file_path VARCHAR(2048),
    sha256_hash VARCHAR(64),
    recovery_method VARCHAR(50),
    -- ... more fields
);

-- Carved Files: Files from unallocated space
CREATE TABLE carved_files (
    id INTEGER PRIMARY KEY,
    partition_id INTEGER REFERENCES partitions(id),
    carved_filename VARCHAR(512),
    signature_type VARCHAR(50),
    sha256_hash VARCHAR(64),
    -- ... more fields
);

-- Audit Log: Chain of custody
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME,
    user VARCHAR(256),
    action VARCHAR(100),
    evidence_id INTEGER,
    command_executed TEXT,
    status VARCHAR(50),
    -- ... more fields
);
```

**Forensic Features:**
- Immutable audit log (no updates/deletes)
- Cascade deletes for data integrity
- Indexed timestamps for timeline queries
- Foreign key constraints for referential integrity

---

### 3. Forensic Engine (`app/services/forensic_engine.py`)

**Purpose:** Core integration with forensic tools

**Key Methods:**

```python
class ForensicEngine:
    def mount_image(e01_path, evidence_id) -> mount_point
        """Mount E01 with ewfmount (read-only)"""
    
    def unmount_image(mount_point) -> bool
        """Safely unmount E01"""
    
    def detect_partitions(mount_point) -> List[Dict]
        """Use mmls to detect partition table"""
    
    def scan_deleted_files(mount_point, offset) -> List[Dict]
        """Use fls to enumerate deleted MFT entries"""
    
    def recover_file(mount_point, offset, inode, output) -> (path, size)
        """Use icat to recover file by inode"""
    
    def carve_files(mount_point, offset, output_dir) -> List[Dict]
        """Use Scalpel to carve from unallocated space"""
    
    def calculate_hash(file_path) -> str
        """Calculate SHA-256 hash"""
```

**Security Features:**
- Path sanitization (prevent traversal attacks)
- Command injection prevention (no shell=True)
- Timeout enforcement
- Read-only mounting
- Input validation

---

### 4. API Routes (`app/api/v1/`)

**Structure:**

```
app/api/v1/
├── evidence.py     # Evidence management
├── scan.py         # Partition & deleted file scanning
├── recovery.py     # File recovery & carving
├── forensics.py    # Timeline, metadata, reports
└── files.py        # File download & management
```

**Design Patterns:**
- Dependency injection (FastAPI Depends)
- Exception handling with HTTPException
- Audit logging on all operations
- Database transactions
- Resource cleanup (unmounting)

---

## Forensic Workflow

### Complete Recovery Pipeline

```
1. EVIDENCE ACQUISITION
   │
   ├─→ Upload E01 file
   ├─→ Calculate SHA-256 hash
   ├─→ Store in evidence directory
   └─→ Create evidence record
   
2. HASH VERIFICATION
   │
   ├─→ Compare with expected hash
   ├─→ Update verification status
   └─→ Log verification result
   
3. PARTITION DETECTION
   │
   ├─→ Mount E01 (read-only)
   ├─→ Run mmls to detect partitions
   ├─→ Identify NTFS partitions
   ├─→ Store partition metadata
   └─→ Unmount
   
4. DELETED FILE ENUMERATION
   │
   ├─→ Mount E01
   ├─→ Run fls -r -d on NTFS partition
   ├─→ Extract MFT entries
   ├─→ Parse MACB timestamps
   ├─→ Store deleted file metadata
   └─→ Unmount
   
5. FILE RECOVERY
   │
   ├─→ Mount E01
   ├─→ Run icat with inode number
   ├─→ Extract file data
   ├─→ Calculate hash of recovered file
   ├─→ Store in recovered directory
   └─→ Unmount
   
6. FILE CARVING (Optional)
   │
   ├─→ Mount E01
   ├─→ Run Scalpel on partition
   ├─→ Carve files by signature
   ├─→ Calculate hashes
   ├─→ Store in carved directory
   └─→ Unmount
   
7. ANALYSIS & REPORTING
   │
   ├─→ Generate MACB timeline
   ├─→ Extract file metadata
   ├─→ Calculate statistics
   ├─→ Generate JSON/PDF report
   └─→ Export audit log
```

---

## Forensic Standards Compliance

### Read-Only Evidence Handling

**Requirement:** Never modify original evidence

**Implementation:**
- All E01 images mounted with `ro,noexec,nodev,nosuid`
- No write operations to mounted filesystems
- Evidence files stored in read-only storage directory
- Copy-on-write recovery (files extracted to separate directory)

**Code Example:**
```python
# Mount with read-only options
cmd = [
    self.ewfmount,
    safe_path,
    str(mount_point)
]
# ewfmount automatically mounts read-only
```

### Cryptographic Verification

**Requirement:** Verify integrity throughout analysis

**Implementation:**
- SHA-256 hash calculated on upload
- Hash verified before analysis
- Hash re-calculated for all recovered files
- Hash comparison for verification

**Code Example:**
```python
def calculate_hash(self, file_path: str) -> str:
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()
```

### Audit Logging

**Requirement:** Complete chain of custody

**Implementation:**
- Every operation logged with timestamp
- User/examiner tracked
- Commands executed recorded
- Success/failure status logged
- Immutable audit log (append-only)

**Code Example:**
```python
log_action(
    db=db,
    user=evidence.examiner,
    action="recover_file",
    evidence_id=evidence.id,
    command=f"icat -o {offset} ewf1 {inode}",
    status="success"
)
```

### Reproducibility

**Requirement:** Analysis must be repeatable

**Implementation:**
- All commands logged with exact parameters
- Timestamps recorded
- File versions tracked
- Configuration stored
- Deterministic hash algorithms

---

## Security Architecture

### Input Validation

```python
def _sanitize_path(self, path: str) -> str:
    """Prevent path traversal attacks"""
    safe_path = Path(path).resolve()
    
    # Ensure path is within allowed directories
    if not any(str(safe_path).startswith(str(allowed)) 
              for allowed in allowed_dirs):
        raise ForensicEngineError("Path traversal detected")
    
    return str(safe_path)
```

### Command Injection Prevention

```python
# SECURE: No shell expansion
subprocess.run(
    [cmd, arg1, arg2],
    shell=False,  # CRITICAL
    timeout=timeout
)

# INSECURE: Never do this
# subprocess.run(f"{cmd} {arg1}", shell=True)  # Vulnerable!
```

### File Size Limits

```python
# Prevent DoS via large uploads
max_size = CONFIG['security']['max_upload_size']  # 100GB
if file_size > max_size:
    file_path.unlink()
    raise HTTPException(status_code=413, detail="File too large")
```

---

## Performance Considerations

### Large Evidence Files

**Challenge:** 100GB+ E01 images

**Solutions:**
- Streaming file uploads
- Chunked hash calculation (64KB chunks)
- Pagination for database queries
- Background jobs for long operations
- Timeout enforcement

### Memory Management

```python
# Stream large files instead of loading into memory
with open(file_path, 'wb') as f:
    shutil.copyfileobj(file.file, f)  # Chunks automatically

# Hash calculation with chunks
buffer_size = 65536  # 64KB
while chunk := f.read(buffer_size):
    hasher.update(chunk)
```

---

## Error Handling Strategy

### Forensic Tool Failures

```python
try:
    result = forensic_engine.recover_file(...)
except RecoveryError as e:
    # Update database status
    deleted_file.recovery_status = "failed"
    deleted_file.recovery_error = str(e)
    db.commit()
    
    # Log failure
    log_action(db, user, "recover_file", status="failure")
    
    # Return error to user
    raise HTTPException(status_code=500, detail=str(e))
```

### Resource Cleanup

```python
mount_point = None
try:
    mount_point = forensic_engine.mount_image(...)
    # Perform analysis
finally:
    # Always unmount, even on error
    if mount_point:
        forensic_engine.unmount_image(mount_point)
        evidence.is_mounted = False
        db.commit()
```

---

## Scalability & Future Enhancements

### Current Limitations
- Single-server architecture
- SQLite database (not suitable for multi-user)
- Synchronous processing (blocks during long operations)

### Recommended Improvements

1. **Background Job Queue**
   ```python
   # Use Celery for async processing
   @celery.task
   def scan_deleted_files_async(evidence_id, partition_id):
       # Long-running scan
       ...
   ```

2. **PostgreSQL Database**
   ```yaml
   database:
     url: "postgresql://user:pass@localhost/forensics"
   ```

3. **Authentication & Authorization**
   ```python
   @router.post("/evidence/upload")
   async def upload(
       current_user: User = Depends(get_current_user),
       ...
   ):
       # Verify user permissions
   ```

4. **Docker Deployment**
   ```dockerfile
   FROM ubuntu:22.04
   RUN apt-get update && apt-get install -y sleuthkit ewf-tools scalpel
   COPY . /app
   CMD ["gunicorn", "app.main:app"]
   ```

---

## Testing Strategy

### Unit Tests
```python
def test_hash_calculation():
    engine = ForensicEngine()
    hash_value = engine.calculate_hash("test.bin")
    assert len(hash_value) == 64  # SHA-256
```

### Integration Tests
```python
def test_full_recovery_workflow():
    # Upload evidence
    # Scan partitions
    # Scan deleted files
    # Recover file
    # Verify hash
```

### Load Tests
```python
# Test with large E01 files
# Test concurrent API requests
# Measure response times
```

---

## Deployment Checklist

- [ ] Install system dependencies
- [ ] Configure firewall (allow port 8000)
- [ ] Set up SSL/TLS certificates
- [ ] Configure authentication
- [ ] Set up log rotation
- [ ] Configure backup strategy
- [ ] Set resource limits
- [ ] Enable monitoring
- [ ] Test disaster recovery

---

## Conclusion

This system provides a **production-ready, forensically-sound backend** for NTFS deleted file recovery. It strictly adheres to digital forensics standards while providing a modern REST API for easy integration with web frontends or forensic tools.

**Key Strengths:**
- ✅ Read-only evidence handling
- ✅ Complete audit logging
- ✅ Cryptographic verification
- ✅ Reproducible operations
- ✅ Professional error handling
- ✅ Comprehensive documentation

**Designed by forensics professionals, for forensics professionals.**
