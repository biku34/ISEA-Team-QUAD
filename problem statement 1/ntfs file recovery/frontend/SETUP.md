# NTFS Forensic Recovery System - Frontend Setup

This is the frontend for the NTFS Forensic Recovery System. It connects to the production-ready FastAPI backend for digital forensics operations.

## Prerequisites

- Node.js 18+ and npm/yarn installed
- Backend API running (see backend documentation)

## Installation

### 1. Clone and Install Dependencies

```bash
# Install dependencies
npm install
# or
yarn install
```

### 2. Configure Environment Variables

Copy the example environment file and update it with your backend API URL:

```bash
cp .env.example .env.local
```

Then edit `.env.local`:

```env
# Backend API Configuration
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_API_BASE_PATH=/api/v1

# Optional: Examiner information
NEXT_PUBLIC_EXAMINER_NAME=Your Name
NEXT_PUBLIC_CASE_NAME=Case-2024-001

# Feature flags
NEXT_PUBLIC_ENABLE_CARVING=true
NEXT_PUBLIC_ENABLE_BATCH_RECOVERY=true
NEXT_PUBLIC_ENABLE_REPORT_GENERATION=true
NEXT_PUBLIC_ENABLE_TIMELINE_ANALYSIS=true
```

## Development

### Start Development Server

```bash
npm run dev
# or
yarn dev
```

The application will be available at `http://localhost:3000`

## Available Views

### 1. Evidence Management
- Upload E01/E02/E03 EnCase images
- Verify cryptographic hashes (SHA-256)
- Track chain of custody
- View upload metadata

### 2. Partitions
- Detect and list disk partitions
- View filesystem type and offsets
- Scan for NTFS structures
- Calculate partition sizes

### 3. Deleted Files
- Enumerate deleted files from partitions
- View inode information
- Display deletion timestamps
- Recover individual files

### 4. File Recovery
- Track recovery status
- Download recovered files
- Verify recovered file hashes
- Batch recovery operations

### 5. File Carving
- Signature-based file recovery
- Configure file types to carve
- Search unallocated space
- Monitor carving progress

### 6. Forensics Analysis
- MACB timeline analysis
- Statistical reporting
- Generate forensic reports
- View comprehensive statistics

### 7. Audit Log
- Complete activity tracking
- Chain of custody documentation
- User action history
- IP address logging

## Backend API Integration

The frontend uses the following API endpoints:

### Evidence Management
- `GET /api/v1/evidence/list` - List all evidence
- `POST /api/v1/evidence/upload` - Upload E01 image
- `POST /api/v1/evidence/verify/{id}` - Verify hash
- `DELETE /api/v1/evidence/{id}` - Delete evidence

### Scanning
- `POST /api/v1/scan/partitions` - Detect partitions
- `GET /api/v1/scan/partitions/{evidence_id}` - List partitions
- `POST /api/v1/scan/deleted` - Scan deleted files
- `GET /api/v1/scan/deleted/{partition_id}` - List deleted files

### Recovery
- `POST /api/v1/recovery/recover/{file_id}` - Recover file
- `POST /api/v1/recovery/carve` - Carve files
- `POST /api/v1/recovery/batch-recover` - Batch recovery

### Forensics
- `GET /api/v1/forensics/timeline/{evidence_id}` - MACB timeline
- `GET /api/v1/forensics/metadata/{file_id}` - File metadata
- `GET /api/v1/forensics/audit/log` - Audit trail
- `POST /api/v1/forensics/report/generate` - Generate report
- `GET /api/v1/forensics/statistics/{evidence_id}` - Statistics

### Files
- `GET /api/v1/files/recovered` - List recovered files
- `GET /api/v1/files/carved` - List carved files
- `GET /api/v1/files/download/recovered/{id}` - Download file
- `GET /api/v1/files/info/recovered/{id}` - File info

## Project Structure

```
.
├── app/
│   ├── layout.tsx           # Root layout with dark theme
│   ├── globals.css          # Global styles and color tokens
│   └── page.tsx             # Main dashboard page
├── components/
│   ├── header.tsx           # App header
│   ├── sidebar.tsx          # Navigation sidebar
│   └── views/               # Feature views
│       ├── evidence.tsx     # Evidence management
│       ├── partitions.tsx   # Partition analysis
│       ├── deleted-files.tsx # Deleted file recovery
│       ├── recovery.tsx     # File recovery status
│       ├── carving.tsx      # File carving operations
│       ├── forensics.tsx    # Forensic analysis
│       └── audit-log.tsx    # Activity tracking
├── lib/
│   └── api-client.ts        # API client utility
├── .env.example             # Environment variable template
└── SETUP.md                 # This file
```

## Styling

The application uses:
- **Tailwind CSS** for utility-first styling
- **Dark theme** optimized for forensic analysis
- **Custom color palette:**
  - Primary: Muted cyan (#4fd1c5)
  - Background: Near-black (#0b0f14)
  - Cards: Dark gray (#121821)
  - Text: Light gray (#e5e7eb)

## Troubleshooting

### Backend Connection Issues

**Error: "Network error: Failed to fetch"**
- Verify backend is running at `NEXT_PUBLIC_API_URL`
- Check CORS configuration on backend
- Ensure API endpoints match version in use

**Error: "API Error: 404"**
- Verify API endpoint paths match backend routes
- Check `NEXT_PUBLIC_API_BASE_PATH` setting

### File Upload Issues

**Error: "Upload failed"**
- Check file size doesn't exceed server limits
- Verify file format is E01/E02/E03
- Ensure backend has sufficient disk space

### Data Display Issues

**Empty results**
- Upload evidence first
- Scan partitions before viewing deleted files
- Verify backend processing completed

## Build for Production

```bash
npm run build
npm run start
```

The production build optimizes all assets and prepares for deployment.

## Deployment Options

### Vercel (Recommended)
```bash
vercel deploy
```

### Docker
```bash
docker build -t forensic-frontend .
docker run -p 3000:3000 forensic-frontend
```

### Traditional Server
```bash
npm run build
npm run start
```

## Security Notes

- All API calls are made to the configured backend URL
- Evidence hashes are verified cryptographically
- Audit log tracks all operations
- Follow chain of custody procedures
- Use HTTPS in production
- Restrict backend API access

## Legal & Ethical Use

This system is designed for **authorized forensic investigations only**:
- ✅ Law enforcement investigations
- ✅ Corporate incident response
- ✅ Academic research (with authorization)
- ✅ Authorized digital forensics training

**NOT for:**
- ❌ Unauthorized system access
- ❌ Privacy violations
- ❌ Illegal data recovery

## Support

For issues or questions:
1. Check backend API documentation
2. Review API responses for error details
3. Verify environment configuration
4. Check browser console for JavaScript errors
5. Refer to backend logs for API issues

---

**Built for forensic integrity and chain of custody compliance**
