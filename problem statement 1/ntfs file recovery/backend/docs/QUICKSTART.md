# Quick Start Guide

## NTFS Forensic Recovery System - 5-Minute Setup

This guide will get you up and running in under 5 minutes.

---

## Prerequisites

- Linux (Ubuntu 20.04+ / Debian 11+)
- Root/sudo access
- 10GB+ free disk space
- Python 3.10+

---

## Installation (Automated)

### Step 1: Install System Dependencies

```bash
cd forensic_recovery_system
chmod +x scripts/install_dependencies.sh
sudo ./scripts/install_dependencies.sh
```

This installs:
- SleuthKit (fls, icat, mmls)
- EWF Tools (ewfmount)
- Scalpel (file carving)
- Python 3 and pip

### Step 2: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure System

```bash
cp config/config.example.yaml config/config.yaml
# Edit config/config.yaml if needed (defaults work fine)
```

### Step 5: Initialize Database

```bash
python scripts/init_db.py
```

### Step 6: Start Server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Server running at:** `http://localhost:8000`

**API Docs:** `http://localhost:8000/docs`

---

## Quick Test (5 Commands)

Open a new terminal and test the API:

```bash
# 1. Check health
curl http://localhost:8000/health

# 2. Upload evidence (replace with your E01 file)
curl -X POST "http://localhost:8000/api/v1/evidence/upload" \
  -F "file=@your_evidence.E01" \
  -F "case_name=TEST-001" \
  -F "examiner=TestUser"

# 3. Scan partitions (use evidence_id from step 2)
curl -X POST "http://localhost:8000/api/v1/scan/partitions" \
  -H "Content-Type: application/json" \
  -d '{"evidence_id": 1}'

# 4. Scan deleted files (use partition_id from step 3)
curl -X POST "http://localhost:8000/api/v1/scan/deleted" \
  -H "Content-Type: application/json" \
  -d '{"evidence_id": 1, "partition_id": 1}'

# 5. List deleted files
curl "http://localhost:8000/api/v1/scan/deleted/1?limit=10"
```

---

## Full Workflow Example

See `examples/workflow_example.sh` for a complete forensic workflow.

```bash
chmod +x examples/workflow_example.sh
./examples/workflow_example.sh
```

---

## Python Client Example

```python
from examples.python_client_example import ForensicRecoveryClient

client = ForensicRecoveryClient("http://localhost:8000")

# Upload evidence
result = client.upload_evidence(
    "evidence.E01",
    "CASE-2024-001",
    "John Doe"
)

evidence_id = result['evidence']['id']

# Scan partitions
partitions = client.scan_partitions(evidence_id)

# Scan deleted files
deleted = client.scan_deleted_files(evidence_id, partition_id=1)

# Recover file
recovered = client.recover_file(deleted_file_id=1)
```

---

## Directory Structure

```
forensic_recovery_system/
├── app/                    # Application code
│   ├── main.py            # FastAPI app
│   ├── models/            # Database models
│   ├── api/               # API endpoints
│   └── services/          # Forensic engine
├── config/                # Configuration
│   └── config.yaml        # Main config
├── storage/               # File storage
│   ├── evidence/          # Uploaded E01 files
│   ├── mount/             # Mount points
│   ├── recovered/         # Recovered files
│   └── carved/            # Carved files
├── logs/                  # Application logs
├── scripts/               # Utility scripts
├── examples/              # Usage examples
└── docs/                  # Documentation
```

---

## Common Issues

### Port Already in Use
```bash
# Change port in config.yaml or use:
uvicorn app.main:app --port 8001
```

### Permission Denied (Mount)
```bash
# Ensure user is in fuse group:
sudo usermod -a -G fuse $USER
# Then logout and login
```

### Command Not Found (fls, icat, etc.)
```bash
# Verify installation:
which fls icat mmls ewfmount scalpel

# If missing, reinstall:
sudo apt-get install sleuthkit ewf-tools scalpel
```

### Database Locked
```bash
# Stop all running instances:
pkill -f uvicorn

# Reset database:
python scripts/init_db.py --reset
```

---

## Production Deployment

### Using Gunicorn (Recommended)

```bash
pip install gunicorn

gunicorn app.main:app \
  -w 4 \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile logs/access.log \
  --error-logfile logs/error.log
```

### Systemd Service

Create `/etc/systemd/system/forensic-recovery.service`:

```ini
[Unit]
Description=NTFS Forensic Recovery System
After=network.target

[Service]
Type=notify
User=forensics
WorkingDirectory=/opt/forensic_recovery_system
Environment="PATH=/opt/forensic_recovery_system/venv/bin"
ExecStart=/opt/forensic_recovery_system/venv/bin/gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable forensic-recovery
sudo systemctl start forensic-recovery
```

---

## Next Steps

1. **Review API Documentation:** `docs/API.md`
2. **Try Python Client:** `examples/python_client_example.py`
3. **Run Full Workflow:** `examples/workflow_example.sh`
4. **Configure for Production:** Update `config/config.yaml`
5. **Add Authentication:** Implement API keys or JWT

---

## Support

- **API Docs:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health
- **Logs:** `logs/forensic_recovery.log`

---

## License

Academic/Educational Use Only

---

**Ready to start your forensic analysis! 🔍**
