# Segmented E01 Upload - Quick Reference

## Overview
The backend now supports **segmented E01 evidence files** (E01, E02, E03, etc.) created by EnCase when splitting large disk images.

## API Endpoints

### 1. Upload Multiple Segments
**Endpoint:** `POST /api/v1/evidence/upload-segments`

Upload a complete set of E01 segments together.

**cURL Example:**
```bash
curl -X POST http://localhost:8000/api/v1/evidence/upload-segments \
  -F "files=@evidence.E01" \
  -F "files=@evidence.E02" \
  -F "files=@evidence.E03" \
  -F "case_name=CASE-2024-001" \
  -F "examiner=Jane Doe" \
  -F "case_number=2024-001" \
  -F "description=Suspect laptop disk image"
```

**Python Example:**
```python
import requests

files = [
    ('files', open('evidence.E01', 'rb')),
    ('files', open('evidence.E02', 'rb')),
    ('files', open('evidence.E03', 'rb'))
]

data = {
    'case_name': 'CASE-2024-001',
    'examiner': 'Jane Doe',
    'description': 'Segmented evidence from suspect device'
}

response = requests.post(
    'http://localhost:8000/api/v1/evidence/upload-segments',
    files=[('files', (f.name, f, 'application/octet-stream')) for _, f in files],
    data=data
)

print(response.json())
```

### 2. Upload Single Segment
**Endpoint:** `POST /api/v1/evidence/upload`

You can still upload individual E01 files. The system will detect if it's part of a segment set.

**Requirements:**
- All segments must be uploaded together using `/upload-segments`
- Segments must start with .E01 (no gaps allowed)
- All segments must have the same base name
- Each segment validates individually with its own SHA-256 hash

## Response Format

```json
{
  "success": true,
  "message": "Segmented evidence uploaded successfully (3 segments)",
  "evidence": {
    "id": 4,
    "filename": "evidence.E01",
    "is_segmented": true,
    "segment_number": 1,
    "total_segments": 3,
    "size_bytes": 5799,
    "sha256_hash": "4faff3e39af87b9c..."
  },
  "segment_info": {
    "total_segments": 3,
    "total_size": 5799,
    "base_name": "evidence",
    "segments": [
      {
        "segment_number": 1,
        "filename": "CASE-2024-001_20260209_133519_evidence.E01",
        "size_bytes": 1933,
        "sha256_hash": "4faff3e39af87b9c..."
      },
      {
        "segment_number": 2,
        "filename": "CASE-2024-001_20260209_133519_evidence.E02",
        "size_bytes": 1933,
        "sha256_hash": "732be1b60bc10c0f..."
      },
      {
        "segment_number": 3,
        "filename": "CASE-2024-001_20260209_133519_evidence.E03",
        "size_bytes": 1933,
        "sha256_hash": "22d8e0e8a8930d66..."
      }
    ]
  }
}
```

## Mounting

Mounting segmented evidence is **automatic**:

```python
# Via API
POST /api/v1/forensics/mount/{evidence_id}

# The system automatically:
# 1. Detects segmented evidence
# 2. Validates all segments are present
# 3. Mounts using the primary .E01 segment
# 4. ewfmount handles remaining segments automatically
```

## Error Handling

### Incomplete Segment Set
```json
{
  "detail": "Segment validation failed: Missing segments: [2]"
}
```

### Invalid File Type
```json
{
  "detail": "Invalid file type: evidence.txt. Allowed: .E01, .E02, .E03..."
}
```

## Testing

Run the included test script:
```bash
cd /home/kali/Desktop/ntfs\ pro
python3 test_segment_upload.py
```

Tests include:
- ✅ Single E01 upload
- ✅ Multi-segment upload (3 segments)
- ✅ Incomplete segment rejection
- ✅ Evidence listing with segment info

## Important Notes

1. **All segments must be uploaded together** - Cannot upload E01 now and E02 later
2. **Segments must be sequential** - E01, E02, E03... (no gaps)
3. **Same directory required** - All segments must be in the same directory for mounting
4. **Individual hashes** - Each segment gets its own SHA-256 hash calculated
5. **Audit trail** - All segment operations are logged with full details

## Forensic Workflow

```
Upload Segments → Validate Set → Calculate Hashes → Store Evidence
                                                           ↓
                                                    Mount Image
                                                           ↓
                                              Scan Partitions
                                                           ↓
                                            Scan Deleted Files
                                                           ↓
                                                Recover Files
```

The segmented evidence handling is transparent after upload - all forensic operations work the same as single E01 files.
