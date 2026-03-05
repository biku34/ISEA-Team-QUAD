# 🔬 NTFS Forensic Recovery Suite

A full-stack digital forensics platform for recovering deleted files, analyzing NTFS artifacts, and detecting disk wipe patterns from E01/EWF forensic images.

```
PS3/
├── backend/         ← Python FastAPI backend
└── frontend/        ← Next.js React frontend
```

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Backend Setup](#2-backend-setup)
  - [3. Frontend Setup](#3-frontend-setup)
- [Running the Application](#-running-the-application)
- [Project Structure](#-project-structure)
- [API Documentation](#-api-documentation)
- [Environment Configuration](#-environment-configuration)
- [Forensic Workflow](#-forensic-workflow)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

| Feature | Description |
|---|---|
| 📁 **Evidence Management** | Upload, verify, and manage E01/EWF forensic images with SHA-256 integrity checks |
| 💾 **Partition Detection** | Automatic NTFS partition identification using The Sleuth Kit (`mmls`) |
| 🗑️ **Deleted File Recovery** | MFT-based enumeration of deleted files via `fls` / `icat` |
| 🔨 **File Carving** | Signature-based carving from unallocated space using Scalpel |
| 🕵️ **NTFS Artifact Extraction** | Extract `$MFT`, `$LogFile`, `$UsnJrnl`, `$Bitmap`, Prefetch, EventLogs, and more |
| 🧹 **Wipe Detection** | Statistical analysis (Shannon entropy, byte frequency, pattern matching) to detect disk wipe operations |
| 📊 **Timeline Generation** | MACB timeline reconstruction for forensic analysis |
| 📝 **Investigation Management** | Create and manage forensic investigations with full audit logging |
| 🔐 **Chain of Custody** | Complete audit trail of all forensic operations |

---

## 🛠 Tech Stack

**Backend**
- Python 3.10+
- FastAPI + Uvicorn
- SQLAlchemy (SQLite)
- The Sleuth Kit (TSK) — `mmls`, `fls`, `icat`, `istat`, `tsk_loaddb`
- libewf — `ewfmount`, `ewfinfo`
- Scalpel (file carving)

**Frontend**
- Next.js 16 (App Router)
- React 19
- TypeScript
- Tailwind CSS + shadcn/ui
- Recharts (data visualization)

---

## 📦 Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+ / Debian / Kali Linux recommended)
- **Python**: 3.10 or higher
- **Node.js**: 18 or higher
- **npm**: 9 or higher

### Required System Tools

Install the following forensic tools before setting up the backend:

```bash
# Ubuntu / Debian / Kali Linux
sudo apt-get update
sudo apt-get install -y \
    sleuthkit \
    libewf-dev \
    libewf-tools \
    ewf-tools \
    scalpel \
    fuse \
    python3-pip \
    python3-venv

# Optional but recommended
sudo apt-get install -y afflib-tools bulk-extractor
```

Verify installations:
```bash
mmls -V        # The Sleuth Kit
ewfinfo -V     # libewf
scalpel -V     # Scalpel
```

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone git@github.com:biku34/ISEA-Team-QUAD.git
cd PS3
```

### 2. Backend Setup

```bash
# Navigate to backend
cd backend

# Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Copy the example config and edit as needed
cp config/config.example.yaml config/config.yaml
# nano config/config.yaml  ← Edit settings if required

# (Optional) Create storage directories manually
# They are auto-created on first startup, but you can pre-create them:
mkdir -p storage/{evidence,artifacts,carved,recovered,reports,mount,temp} logs
```

### 3. Frontend Setup

```bash
# In a new terminal, navigate to frontend
cd frontend

# Install Node dependencies
npm install
# or if you prefer pnpm:
# pnpm install
```

---

## ▶️ Running the Application

### Start the Backend

```bash
cd backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at: `http://localhost:8000`  
Interactive API docs (Swagger UI): `http://localhost:8000/api/v1/docs`

### Start the Frontend

```bash
cd frontend
npm run dev
```

The UI will be available at: `http://localhost:3000`

> **Note:** Both servers must be running simultaneously. The frontend proxies API requests to the backend at `http://localhost:8000`.

---

## 📁 Project Structure

```
PS3/
│
├── .gitignore
├── README.md
│
├── backend/                           # Backend — FastAPI Application
│   ├── app/
│   │   ├── main.py                    # FastAPI app entrypoint
│   │   ├── database.py                # SQLAlchemy DB setup
│   │   ├── api/v1/                    # REST API route handlers
│   │   │   ├── evidence.py            # Evidence upload & management
│   │   │   ├── scan.py                # Partition & file scanning
│   │   │   ├── recovery.py            # File recovery
│   │   │   ├── forensics.py           # Forensic analysis
│   │   │   ├── artifacts.py           # NTFS artifact extraction
│   │   │   ├── wipe.py                # Wipe detection
│   │   │   ├── investigation.py       # Investigation management
│   │   │   └── files.py               # File downloads
│   │   ├── models/                    # SQLAlchemy ORM models
│   │   └── services/                  # Business logic
│   │       ├── ntfs_parser.py         # NTFS / TSK integration
│   │       ├── wipe_detector.py       # Wipe pattern analysis engine
│   │       └── ...
│   ├── config/
│   │   └── config.example.yaml        # Example configuration
│   ├── storage/                       # Runtime data (gitignored)
│   │   ├── evidence/                  # Uploaded E01 images
│   │   ├── artifacts/                 # Extracted NTFS artifacts
│   │   ├── carved/                    # Scalpel carved files
│   │   ├── recovered/                 # Recovered files
│   │   ├── reports/                   # Generated forensic reports
│   │   ├── mount/                     # ewfmount mount points
│   │   └── temp/                      # Temporary working files
│   ├── logs/                          # Application logs (gitignored)
│   ├── docs/                          # Technical documentation
│   ├── scripts/                       # Helper scripts
│   ├── requirements.txt
│   ├── install_tools.sh               # System tool installer script
│   └── start_server.sh                # Quick start script
│
└── frontend/                          # Frontend — Next.js Application
    ├── app/                           # Next.js App Router pages
    ├── components/
    │   ├── views/                     # Page-level view components
    │   │   ├── dashboard.tsx
    │   │   ├── evidence.tsx
    │   │   ├── file-recovery.tsx
    │   │   ├── wipe-detection.tsx
    │   │   └── ...
    │   └── ui/                        # Reusable shadcn/ui components
    ├── hooks/                         # React custom hooks
    ├── lib/                           # Utilities and API client
    ├── styles/                        # Global CSS
    ├── public/                        # Static assets
    ├── package.json
    └── next.config.mjs
```

---

## 📖 API Documentation

Once the backend is running, full interactive API documentation is available at:

- **Swagger UI**: `http://localhost:8000/api/v1/docs`
- **ReDoc**: `http://localhost:8000/api/v1/redoc`

### Key Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/evidence/upload` | Upload an E01/EWF forensic image |
| `POST` | `/api/v1/evidence/verify/{id}` | Verify evidence hash integrity |
| `POST` | `/api/v1/scan/partitions` | Detect NTFS partitions |
| `POST` | `/api/v1/scan/deleted` | Enumerate deleted files |
| `POST` | `/api/v1/recovery/recover/{inode}` | Recover a specific file by inode |
| `POST` | `/api/v1/recovery/carve` | Run Scalpel file carving |
| `POST` | `/api/v1/artifacts/extract` | Extract NTFS system artifacts |
| `POST` | `/api/v1/wipe/scan` | Run wipe detection analysis |
| `GET` | `/api/v1/wipe/results/{id}` | Get wipe scan results |
| `GET` | `/api/v1/files/download/{id}` | Download a recovered file |
| `GET` | `/health` | Backend health check |

---

## ⚙️ Environment Configuration

### Backend (`backend/config/config.yaml`)

Copy `config.example.yaml` to `config.yaml` and adjust as needed:

```yaml
app:
  name: "NTFS Forensic Recovery System"
  version: "1.0.0"
  host: "0.0.0.0"
  port: 8000
  debug: true

api:
  prefix: "/api/v1"
  docs_url: "/api/v1/docs"
  redoc_url: "/api/v1/redoc"
  cors_origins:
    - "http://localhost:3000"
```

### Frontend

The frontend uses Next.js built-in environment variable support. Create `frontend/.env.local` if you need to override the API URL:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## 🔍 Forensic Workflow

```
1. Upload Evidence     →  POST /evidence/upload       (E01/EWF image)
2. Verify Integrity    →  POST /evidence/verify/{id}  (SHA-256 check)
3. Detect Partitions   →  POST /scan/partitions       (mmls)
4. Scan Deleted Files  →  POST /scan/deleted          (fls / MFT)
5. Extract Artifacts   →  POST /artifacts/extract     ($MFT, $LogFile, etc.)
6. Recover Files       →  POST /recovery/recover      (icat)
7. Carve Unallocated   →  POST /recovery/carve        (Scalpel)
8. Analyze Wipe        →  POST /wipe/scan             (entropy analysis)
9. Download Results    →  GET  /files/download/{id}
```

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-new-feature`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/my-new-feature`
5. Open a Pull Request

---

## 📄 License

This project is intended for lawful forensic investigation purposes only.  
Unauthorized use against systems you do not own or have explicit permission to analyze is strictly prohibited.

---

> **Built for digital forensics professionals and researchers.**  
> Always ensure proper legal authorization before analyzing any forensic evidence.
