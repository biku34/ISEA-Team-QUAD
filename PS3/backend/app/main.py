"""
Main FastAPI application for NTFS Forensic Recovery System.

FORENSIC BACKEND API
- Evidence upload and verification
- Partition detection
- Deleted file enumeration
- File recovery and carving
- Timeline generation
- Audit logging
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import time
import yaml
from pathlib import Path
from loguru import logger
import sys

# Configure logging
logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>",
    level="INFO"
)
logger.add(
    "./logs/forensic_recovery.log",
    rotation="100 MB",
    retention="30 days",
    format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}",
    level="DEBUG"
)

# Load configuration
config_path = Path(__file__).parent.parent / "config" / "config.yaml"
if not config_path.exists():
    config_path = Path(__file__).parent.parent / "config" / "config.example.yaml"

with open(config_path, 'r') as f:
    CONFIG = yaml.safe_load(f)

# Import database
from app.database import init_database, engine

# Import API routes
from app.api.v1 import evidence, scan, recovery, forensics, files, investigation, artifacts, wipe


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for application startup/shutdown.
    """
    # Startup
    logger.info("🚀 Starting NTFS Forensic Recovery System")
    
    # Create storage directories
    storage_dirs = [
        'storage/evidence',
        'storage/mount',
        'storage/recovered',
        'storage/carved',
        'storage/temp',
        'storage/reports',
        'storage/artifacts',   # Phase 1: NTFS artifact extraction
        'logs'
    ]
    
    for directory in storage_dirs:
        Path(directory).mkdir(parents=True, exist_ok=True)
        logger.info(f"✓ Created directory: {directory}")
    
    # Initialize database
    try:
        init_database()
        logger.info("✓ Database initialized successfully")
    except Exception as e:
        logger.error(f"✗ Database initialization failed: {e}")
        raise
    
    logger.info("✓ Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("👋 Shutting down NTFS Forensic Recovery System")
    
    # Close database connections
    engine.dispose()
    logger.info("✓ Database connections closed")


# Create FastAPI application
app = FastAPI(
    title=CONFIG['app']['name'],
    version=CONFIG['app']['version'],
    description="""
    ## NTFS Forensic Recovery System - Backend API
    
    Production-ready forensic backend for automated deleted file recovery from NTFS EnCase images.
    
    ### Features
    - 🔍 **Evidence Management**: Upload and verify E01 forensic images
    - 💾 **Partition Detection**: Automatic NTFS partition identification
    - 🗑️ **Deleted File Scanning**: MFT-based enumeration via SleuthKit
    - ♻️ **File Recovery**: icat-based recovery of deleted files
    - 🔨 **File Carving**: Scalpel-based recovery from unallocated space
    - 📊 **Timeline Generation**: MACB timeline reconstruction
    - 🔐 **Chain of Custody**: Complete audit logging
    - ✅ **Hash Verification**: SHA-256 integrity checking
    
    ### Forensic Standards
    - Read-only evidence handling
    - Complete audit trail
    - Cryptographic verification
    - Reproducible operations
    
    ### Workflow
    1. Upload E01 image → POST /api/v1/evidence/upload
    2. Verify hash → POST /api/v1/evidence/verify/{id}
    3. Scan partitions → POST /api/v1/scan/partitions
    4. Scan deleted files → POST /api/v1/scan/deleted
    5. Recover files → POST /api/v1/recovery/recover/{inode}
    6. Carve files → POST /api/v1/recovery/carve
    7. Download files → GET /api/v1/files/download/{id}
    """,
    docs_url=CONFIG['api']['docs_url'],
    redoc_url=CONFIG['api']['redoc_url'],
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=CONFIG['api']['cors_origins'],
    allow_credentials=CONFIG['api']['cors_allow_credentials'],
    allow_methods=CONFIG['api']['cors_allow_methods'],
    allow_headers=CONFIG['api']['cors_allow_headers'],
)

# Configure multipart upload limits for large E01 files
# This allows uploading multiple segments that total up to 110GB
from starlette.middleware import Middleware
from starlette.datastructures import UploadFile as StarletteUploadFile

# Monkey patch to increase the spool size threshold (files below this stay in memory)
StarletteUploadFile.spool_max_size = 1024 * 1024 * 100  # 100MB threshold before spooling to disk


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add processing time header to all responses"""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Audit logging middleware
@app.middleware("http")
async def audit_logging(request: Request, call_next):
    """Log all API requests for forensic audit trail"""
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Log request
    logger.info(f"{request.method} {request.url.path} from {client_ip}")
    
    response = await call_next(request)
    
    # Log response status
    logger.info(f"{request.method} {request.url.path} → {response.status_code}")
    
    return response


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if CONFIG['app']['debug'] else "An unexpected error occurred",
            "path": request.url.path
        }
    )


# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """
    Health check endpoint for monitoring.
    Returns system status and version.
    """
    return {
        "status": "healthy",
        "version": CONFIG['app']['version'],
        "name": CONFIG['app']['name'],
        "timestamp": time.time()
    }


# API version info
@app.get("/", tags=["System"])
async def root():
    """
    Root endpoint with API information.
    """
    return {
        "name": CONFIG['app']['name'],
        "version": CONFIG['app']['version'],
        "docs": CONFIG['api']['docs_url'],
        "api_prefix": CONFIG['api']['prefix'],
        "endpoints": {
            "evidence": f"{CONFIG['api']['prefix']}/evidence",
            "scan": f"{CONFIG['api']['prefix']}/scan",
            "recovery": f"{CONFIG['api']['prefix']}/recovery",
            "forensics": f"{CONFIG['api']['prefix']}/forensics",
            "files": f"{CONFIG['api']['prefix']}/files"
        }
    }


# Include API routers
prefix = CONFIG['api']['prefix']

app.include_router(
    evidence.router,
    prefix=f"{prefix}/evidence",
    tags=["Evidence Management"]
)

app.include_router(
    scan.router,
    prefix=f"{prefix}/scan",
    tags=["Analysis & Scanning"]
)

app.include_router(
    recovery.router,
    prefix=f"{prefix}/recovery",
    tags=["File Recovery"]
)

app.include_router(
    forensics.router,
    prefix=f"{prefix}/forensics",
    tags=["Forensic Analysis"]
)

app.include_router(
    files.router,
    prefix=f"{prefix}/files",
    tags=["File Management"]
)

app.include_router(
    investigation.router,
    prefix=f"{prefix}/investigation",
    tags=["Investigation Management"]
)

app.include_router(
    artifacts.router,
    prefix=f"{prefix}/artifacts",
    tags=["NTFS Artifact Extraction"]
)

app.include_router(
    wipe.router,
    prefix=f"{prefix}/wipe",
    tags=["Wipe Detection"]
)


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=CONFIG['app']['host'],
        port=CONFIG['app']['port'],
        reload=CONFIG['app']['debug'],
        log_level="info"
    )
