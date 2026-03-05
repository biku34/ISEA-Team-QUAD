# NTFS Forensic Recovery System - Backend API

## Overview
Production-ready forensic backend for automated deleted file recovery from NTFS EnCase images (.E01/.E02/.E03). Designed for academic digital forensics with full chain-of-custody compliance.

## 🔬 Forensic Standards Compliance
- ✅ Read-only evidence handling
- ✅ Cryptographic hash verification (SHA-256)
- ✅ Complete audit logging
- ✅ Reproducible analysis
- ✅ NTFS MFT metadata extraction
- ✅ Timeline reconstruction (MACB timestamps)
- ✅ File carving from unallocated space

## 🏗️ Architecture

```
┌─────────────┐
│   Web UI    │
└──────┬──────┘
       │ REST API
┌──────▼──────────────────────┐
│   FastAPI Backend           │
│  ┌──────────────────────┐  │
│  │  Forensic Engine     │  │
│  │  - SleuthKit (fls)   │  │
│  │  - EWF (ewfmount)    │  │
│  │  - Scalpel (carving) │  │
│  └──────────────────────┘  │
└──────┬──────────────────────┘
       │
┌──────▼──────┐
│  SQLite DB  │
│  + Evidence │
└─────────────┘
```

## 📋 System Requirements

### Operating System
- Linux (Ubuntu 20.04+ / Debian 11+ recommended)
- Root/sudo access for mounting

### Dependencies
```bash
# Forensic Tools
sudo apt-get update
sudo apt-get install -y \
    sleuthkit \
    ewf-tools \
    scalpel \
    python3.10 \
    python3-pip \
    fuse \
    libewf-dev

# Python Packages (see requirements.txt)
```

## 🚀 Installation

### 1. Clone Repository
```bash
git clone <repository>
cd forensic_recovery_system
```

### 2. Install System Dependencies
```bash
chmod +x scripts/install_dependencies.sh
sudo ./scripts/install_dependencies.sh
```

### 3. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Configure System
```bash
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your settings
```

### 5. Initialize Database
```bash
python scripts/init_db.py
```

### 6. Start API Server
```bash
# Development
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

## 📡 API Documentation

### Interactive Docs
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Core Endpoints

#### Evidence Management
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/evidence/upload` | POST | Upload E01 image |
| `/api/v1/evidence/verify` | POST | Verify image hash |
| `/api/v1/evidence/list` | GET | List all evidence |

#### Analysis
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/scan/partitions` | POST | Detect partitions |
| `/api/v1/scan/deleted` | POST | Enumerate deleted files |
| `/api/v1/recover/{inode}` | POST | Recover specific file |
| `/api/v1/carve` | POST | File carving |

#### Results
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/files/deleted` | GET | List deleted files |
| `/api/v1/files/recovered` | GET | List recovered files |
| `/api/v1/files/download/{id}` | GET | Download file |

#### Forensics
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/timeline` | GET | MACB timeline |
| `/api/v1/metadata/{inode}` | GET | MFT metadata |
| `/api/v1/audit/log` | GET | Audit trail |
| `/api/v1/report/generate` | POST | Generate report |

## 🔐 Security Features

1. **Read-Only Evidence Mounting**
   - All images mounted with `ro,noexec,nodev,nosuid`
   - No write operations to evidence

2. **Command Injection Prevention**
   - Input sanitization
   - Subprocess isolation
   - Path traversal protection

3. **Audit Logging**
   - Every operation logged with timestamp
   - User tracking
   - Action categorization

4. **Hash Verification**
   - SHA-256 verification before analysis
   - Chain of custody documentation

## 📂 Project Structure

```
forensic_recovery_system/
├── app/
│   ├── main.py                 # FastAPI application
│   ├── config.py               # Configuration loader
│   ├── database.py             # Database connection
│   ├── models/                 # SQLAlchemy models
│   │   ├── evidence.py
│   │   ├── partition.py
│   │   ├── deleted_file.py
│   │   └── audit_log.py
│   ├── api/
│   │   └── v1/
│   │       ├── evidence.py     # Evidence endpoints
│   │       ├── scan.py         # Scanning endpoints
│   │       ├── recovery.py     # Recovery endpoints
│   │       └── forensics.py    # Forensic endpoints
│   ├── services/
│   │   ├── forensic_engine.py  # Core forensic logic
│   │   ├── hash_service.py     # Hashing operations
│   │   ├── mount_service.py    # Image mounting
│   │   └── carving_service.py  # File carving
│   └── schemas/                # Pydantic schemas
├── config/
│   ├── config.yaml             # Main configuration
│   └── scalpel.conf            # Scalpel configuration
├── scripts/
│   ├── install_dependencies.sh # System setup
│   └── init_db.py              # Database initialization
├── storage/
│   ├── evidence/               # E01 uploads
│   ├── mount/                  # Mount points
│   ├── recovered/              # Recovered files
│   └── carved/                 # Carved files
├── logs/                       # Application logs
├── requirements.txt
└── README.md
```

## 🔬 Forensic Workflow

### 1. Evidence Acquisition
```bash
curl -X POST "http://localhost:8000/api/v1/evidence/upload" \
  -F "file=@evidence.E01" \
  -F "case_name=Case-2024-001" \
  -F "examiner=John Doe"
```

### 2. Hash Verification
```bash
curl -X POST "http://localhost:8000/api/v1/evidence/verify" \
  -H "Content-Type: application/json" \
  -d '{"evidence_id": 1, "expected_hash": "abc123..."}'
```

### 3. Partition Detection
```bash
curl -X POST "http://localhost:8000/api/v1/scan/partitions" \
  -H "Content-Type: application/json" \
  -d '{"evidence_id": 1}'
```

### 4. Deleted File Enumeration
```bash
curl -X POST "http://localhost:8000/api/v1/scan/deleted" \
  -H "Content-Type: application/json" \
  -d '{"evidence_id": 1, "partition_id": 1}'
```

### 5. File Recovery
```bash
curl -X POST "http://localhost:8000/api/v1/recover/12345" \
  -H "Content-Type: application/json" \
  -d '{"evidence_id": 1}'
```

### 6. File Carving
```bash
curl -X POST "http://localhost:8000/api/v1/carve" \
  -H "Content-Type: application/json" \
  -d '{"evidence_id": 1, "partition_id": 1}'
```

## 📊 Database Schema

### Evidence Table
- id, filename, upload_time, sha256_hash, size_bytes, case_name, examiner

### Partitions Table
- id, evidence_id, partition_number, start_offset, filesystem_type, size_bytes

### Deleted Files Table
- id, partition_id, inode, filename, size_bytes, deleted_time, mft_entry

### Recovered Files Table
- id, deleted_file_id, recovery_time, sha256_hash, file_path

### Audit Log Table
- id, timestamp, user, action, evidence_id, details, ip_address

## 🧪 Testing

```bash
# Run unit tests
pytest tests/

# Run with coverage
pytest --cov=app tests/

# Integration tests
pytest tests/integration/
```

## 📝 Sample Usage

See `examples/` directory for:
- Python client examples
- cURL command examples
- Forensic report templates

## ⚠️ Legal & Ethical Use

This system is designed for:
- ✅ Academic research
- ✅ Authorized forensic investigations
- ✅ Digital forensics training
- ✅ Incident response

**NOT for:**
- ❌ Unauthorized access to systems
- ❌ Privacy violations
- ❌ Illegal data recovery

## 🤝 Contributing

This is an academic project. Contributions should maintain forensic integrity standards.

## 📄 License

Academic/Educational Use Only

## 📞 Support

For issues or questions, refer to documentation or submit an issue.

---
**Built with forensic integrity in mind 🔍**
