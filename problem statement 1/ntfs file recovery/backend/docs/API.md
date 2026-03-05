# API Documentation

## NTFS Forensic Recovery System - REST API Reference

**Base URL:** `http://localhost:8000/api/v1`

**Interactive Docs:** `http://localhost:8000/docs`

---

## Recommended Investigation Workflow

To perform a standard forensic acquisition and analysis, follow these steps in order:

1.  **Ingestion**: Upload the forensic image using `POST /evidence/upload`. Use `POST /evidence/verify/{id}` to confirm the hash matches the original acquisition.
2.  **Partition Discovery**: Run `POST /scan/partitions` to detect available partitions and identifying NTFS volumes.
3.  **File System Navigation**:
    *   Use `GET /scan/hierarchy/{partition_id}` to see the full list of files (allocated and deleted).
    *   Use `GET /scan/ls/{partition_id}` to drill down into specific folders interactively.
4.  **Targeted Recovery**:
    *   If you know the file was deleted but the MFT is intact, use `POST /scan/deleted` followed by `POST /recovery/recover/{id}`.
5.  **Unallocated Space Recovery (Carving)**:
    *   For files without file system entries, use `POST /recovery/carve` to start signature-based extraction.
    *   Poll `GET /recovery/carve/status/{session_id}` for progress (0-100%).
    *   Check `GET /recovery/carve/results/{session_id}` for incremental findings during the process.
6.  **Reporting**: Generate a final report summarizing all findings with `POST /forensics/report/generate`.
7.  **Evidence Disposition**: Once the case is closed, use `POST /investigation/reset` to securely clear the evidence image and session data.

---

## Authentication
Currently, the API does not require authentication. In production, implement:
- API keys
- JWT tokens
- Role-based access control

---

## Evidence Management

### Upload Evidence
Upload an E01 forensic disk image or primary segment.

**Endpoint:** `POST /evidence/upload`

**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/evidence/upload" \
  -F "file=@evidence.E01" \
  -F "case_name=CASE-2024-001" \
  -F "examiner=John Doe"
```

---

### Verify Evidence Hash
Verify evidence integrity using SHA-256.

**Endpoint:** `POST /evidence/verify/{evidence_id}`

---

### List Evidence
List all uploaded evidence files.

**Endpoint:** `GET /evidence/list`

---

## Partition Scanning

### Scan Partitions
Detect partitions using mmls (SleuthKit).

**Endpoint:** `POST /scan/partitions`

---

### Get Partitions
List detected partitions for evidence.

**Endpoint:** `GET /scan/partitions/{evidence_id}`

---

## File System Navigation

### Get Complete Hierarchy
Get a flat list of all directory entries (allocated and deleted) in a partition. Useful for tree-view building.

**Endpoint:** `GET /scan/hierarchy/{partition_id}`

---

### List Directory
List direct children of a specific directory inode.

**Endpoint:** `GET /scan/ls/{partition_id}`

**Parameters:**
- `inode` (optional): Directory inode to list. Defaults to root.

---

## Deleted File Scanning

### Scan for Deleted Files (MFT Based)
Enumerate deleted files by scanning the Master File Table.

**Endpoint:** `POST /scan/deleted`

---

### List Deleted Files
Get paginated list of discovered deleted files.

**Endpoint:** `GET /scan/deleted/{partition_id}`

---

## File Recovery

### Recover Deleted File (icat)
Recover a specific file using its inode.

**Endpoint:** `POST /recovery/recover/{deleted_file_id}`

---

### Carve Files (Scalpel)
Initiate signature-based carving from unallocated space. This is a background task.

**Endpoint:** `POST /recovery/carve`

**Response:**
```json
{
  "success": true,
  "message": "Carving task initiated in background",
  "session": {
    "session_id": "carve_1_1_abc123",
    "status": "queued",
    "progress_percentage": 0
  }
}
```

---

### Carving Status & Progress
Check the real-time progress of a carving session.

**Endpoint:** `GET /recovery/carve/status/{session_id}`

**Response:**
```json
{
  "session_id": "carve_1_1_abc123",
  "status": "in_progress",
  "progress_percentage": 45,
  "progress_message": "In Progress: Found 12 files so far... (45%)"
}
```

---

### Carving Results
Retrieve files found so far by an active or completed carving session.

**Endpoint:** `GET /recovery/carve/results/{session_id}`

---

## Forensic Analysis

### Generate Timeline
Generate MACB timeline from file metadata.

**Endpoint:** `GET /forensics/timeline/{evidence_id}`

---

### Generate Report
Generate comprehensive forensic report.

**Endpoint:** `POST /forensics/report/generate`

---

## Investigation Management

### Reset Investigation
Completely reset the forensic environment (terminate processes, unmount images, reset DB).

**Endpoint:** `POST /investigation/reset`

**CAUTION:** This is a destructive operation. See [Investigation Reset Guide](INVESTIGATION_RESET.md) for details.

---

## Error Responses

All endpoints return standard HTTP status codes:
- `200 OK`: Success
- `201 Created`: Resource created
- `202 Accepted`: Background task accepted
- `400 Bad Request`: Invalid input
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource already exists
- `500 Internal Server Error`: Server error

**Error Response Format:**
```json
{
  "error": "Error type",
  "detail": "Detailed error message",
  "path": "/api/v1/endpoint"
}
```

---

## Support
- Interactive API docs: `http://localhost:8000/docs`
- OpenAPI spec: `http://localhost:8000/openapi.json`
