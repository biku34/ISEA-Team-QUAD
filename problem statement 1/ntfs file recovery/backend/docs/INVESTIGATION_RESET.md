# Investigation Reset Guide

The Investigation Reset functionality is a critical maintenance operation designed to clear the forensic environment between cases or after a testing cycle.

## Overview

The "End Investigation" endpoint performs a destructive reset of the application state. It ensures that no data from a previous case persists into a new one, maintaining the integrity and isolation of forensic investigations.

**Endpoint:** `POST /api/v1/investigation/reset`

## Operations Performed

When this endpoint is called, the following sequence of actions occurs:

### 1. Process Termination
The system identifies all active **Scalpel** carving processes.
- It uses `pgrep` to find all processes associated with the carving tool.
- It sends a SIGKILL (`kill -9`) to ensure immediate termination, preventing further disk writes or CPU consumption.

### 2. Evidence Unmounting
The system identifies all active mount points in the configured `mount_dir` (e.g., `storage/mount/`).
- It looks for directories starting with `evidence_`.
- It attempts a clean unmount using `ewfunmount`.
- If a clean unmount fails, it performs a lazy unmount using `fusermount3 -u -z`.
- It removes the mount point directories once they are no longer in use.

### 3. Database Reset
The system resets the entire database schema.
- **Drop All Tables:** All existing tables (`evidence`, `partitions`, `deleted_files`, `carved_files`, `audit_logs`, etc.) are dropped.
- **Initialize Database:** The schema is recreated from scratch, resulting in a completely empty database ready for new data.

## Usage

### CURL Example
```bash
curl -X POST "http://localhost:8000/api/v1/investigation/reset"
```

### Successful Response
```json
{
  "success": true,
  "message": "Investigation environment has been reset",
  "details": {
    "processes_terminated": 2,
    "mounts_cleaned": 1,
    "database_reset": true
  }
}
```

## Security & Forensic Considerations

> [!CAUTION]
> **This is a destructive operation.** All metadata, audit logs, and tracking information within the database will be PERMANENTLY DELETED.

- **Data Retention:** This process DOES NOT delete the actual evidence files in `storage/evidence/` or the recovered/carved files in `storage/recovered/` and `storage/carved/`. This is by design to prevent accidental loss of recovered evidence. Manual cleanup of these directories is required if needed.
- **Audit Trail:** The request to reset is logged in the application logs, but since the database is reset, the `audit_logs` table within the database is cleared.
- **Examiner Responsibility:** It is the examiner's responsibility to ensure that all necessary reports and data have been exported before initiating a reset.
