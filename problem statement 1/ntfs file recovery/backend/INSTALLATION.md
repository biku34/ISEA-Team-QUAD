# Backend Requirements & Tools Installation Guide

## Overview
The NFSU (NTFS Forensic Recovery System) backend requires both **Python packages** and **external forensic tools** to function properly.

## Python Dependencies

### Installation
```bash
cd "ntfs pro"
pip install -r requirements.txt
```

### Key Packages
- **FastAPI** - Web framework
- **SQLAlchemy** - Database ORM
- **Celery** - Background task processing
- **Loguru** - Advanced logging
- **ReportLab** - PDF report generation
- **Cryptography** - Hash verification and security

See `requirements.txt` for the complete list with version requirements.

---

## External Forensic Tools

These are **system-level tools** that must be installed separately from Python packages.

### Required Tools

#### 1. **The Sleuth Kit (TSK)**
**Purpose:** Core forensic analysis - partition detection, file system analysis, file recovery

**Commands Provided:**
- `mmls` - Display partition table
- `fls` - List files and directories
- `icat` - Extract file contents by inode
- `istat` - File metadata information
- `fsstat` - File system details

**Installation:**
```bash
# Ubuntu/Debian
sudo apt-get install sleuthkit

# RHEL/CentOS/Fedora
sudo yum install sleuthkit

# macOS
brew install sleuthkit
```

**Verify:**
```bash
mmls -V
```

---

#### 2. **libewf (Expert Witness Format Tools)**
**Purpose:** Mount and read E01/EWF forensic disk images

**Commands Provided:**
- `ewfmount` - Mount E01 files as raw images
- `ewfinfo` - Display E01 metadata
- `ewfacquire` - Create E01 images

**Installation:**
```bash
# Ubuntu/Debian
sudo apt-get install libewf-tools ewf-tools

# RHEL/CentOS/Fedora
sudo yum install libewf ewf-tools

# macOS
brew install libewf
```

**Verify:**
```bash
ewfinfo -V
```

---

#### 3. **Scalpel**
**Purpose:** File carving - recover deleted files from unallocated disk space

**Configuration:** `/etc/scalpel/scalpel.conf`

**Installation:**
```bash
# Ubuntu/Debian
sudo apt-get install scalpel

# RHEL/CentOS/Fedora
sudo yum install scalpel

# macOS
brew install scalpel
```

**Verify:**
```bash
scalpel -V
```

---

### Optional Tools (Recommended)

#### **AFF Tools**
Advanced Forensic Format support
```bash
sudo apt-get install afflib-tools
```

#### **bulk_extractor**
Advanced data extraction
```bash
sudo apt-get install bulk-extractor
```

---

## Automated Installation

### Using the Installation Script

We provide an automated script that detects your OS and installs all required tools:

```bash
cd "ntfs pro"
./install_tools.sh
```

The script will:
1. Detect your operating system
2. Install all required forensic tools
3. Verify each installation
4. Report any errors

---

## Complete Setup Guide

### Step 1: Clone/Download Repository
```bash
cd /path/to/project
```

### Step 2: Install System Forensic Tools
```bash
cd "ntfs pro"
./install_tools.sh
```

### Step 3: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Create Required Directories
```bash
mkdir -p forensics/{evidence,mounts,output,recovered,carved}
```

### Step 5: Set Up Configuration
```bash
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your settings
```

### Step 6: Initialize Database
```bash
alembic upgrade head
```

### Step 7: Run the Application
```bash
# Development mode
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Production mode
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

---

## Verification

### Verify All Tools Are Installed

```bash
# Check Python packages
pip list | grep -E "(fastapi|sqlalchemy|celery)"

# Check Sleuth Kit
mmls -V
fls -V
icat -V

# Check libewf
ewfinfo -V
ewfmount -V

# Check Scalpel
scalpel -V
```

### Test Basic Functionality

```bash
# Test mmls (should show help)
mmls -h

# Test ewfinfo (should show usage)
ewfinfo -h

# Test scalpel (should show help)
scalpel -h
```

---

## Troubleshooting

### Issue: Command not found after installation

**Solution:**
```bash
# Reload shell profile
source ~/.bashrc  # or ~/.zshrc

# Check if PATH includes /usr/local/bin
echo $PATH

# Try finding the command manually
which mmls
which ewfinfo
```

### Issue: Permission denied errors

**Solution:**
```bash
# Give proper permissions to forensics directories
sudo chown -R $USER:$USER forensics/
chmod -R 755 forensics/
```

### Issue: E01 mounting fails

**Solution:**
```bash
# Install FUSE support
sudo apt-get install fuse libfuse-dev

# Load FUSE kernel module
sudo modprobe fuse

# Add user to fuse group
sudo usermod -a -G fuse $USER
```

### Issue: Python package conflicts

**Solution:**
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install packages in isolated environment
pip install -r requirements.txt
```

---

## System Requirements

### Minimum
- **OS:** Linux (Ubuntu 20.04+, RHEL 8+), macOS 11+
- **Python:** 3.9 or higher
- **RAM:** 4GB
- **Disk:** 100GB+ for evidence storage

### Recommended
- **OS:** Ubuntu 22.04 LTS or Debian 12
- **Python:** 3.11
- **RAM:** 16GB+
- **Disk:** 1TB+ SSD
- **CPU:** 4+ cores

---

## Development vs Production

### Development
```bash
# Install with dev tools
pip install -r requirements.txt

# Run with hot reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Production
```bash
# Install without dev tools
pip install -r requirements.txt --no-dev

# Run with Gunicorn
gunicorn app.main:app \
  -w 4 \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile /var/log/nfsu/access.log \
  --error-logfile /var/log/nfsu/error.log
```

---

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Verify all tools are installed correctly
3. Check application logs in `logs/` directory
4. Review configuration in `config/config.yaml`

---

## References

- **Sleuth Kit:** https://www.sleuthkit.org/
- **libewf:** https://github.com/libyal/libewf
- **Scalpel:** https://github.com/sleuthkit/scalpel
- **FastAPI:** https://fastapi.tiangolo.com/
- **SQLAlchemy:** https://www.sqlalchemy.org/
