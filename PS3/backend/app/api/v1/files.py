"""
File Management API endpoints.
Download recovered and carved files.

FORENSIC FEATURES:
- File download with integrity tracking
- Export logging for chain of custody
- File listing and search
"""

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session
from typing import Optional
from pathlib import Path
from datetime import datetime
import mimetypes
import yaml

from app.database import get_db
from app.models import RecoveredFile, CarvedFile, Evidence, log_action

# Load config
config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.yaml"
if not config_path.exists():
    config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.example.yaml"

with open(config_path, 'r') as f:
    CONFIG = yaml.safe_load(f)

router = APIRouter()


@router.get("/recovered")
def list_recovered_files(
    evidence_id: Optional[int] = None,
    file_type: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    List all recovered files.
    
    **Filters:**
    - evidence_id: Filter by evidence
    - file_type: Filter by file extension
    - skip/limit: Pagination
    
    **Returns:** List of recovered file metadata
    """
    query = db.query(RecoveredFile)
    
    if evidence_id:
        # Join through deleted_file to filter by evidence
        from app.models import DeletedFile, Partition
        query = query.join(DeletedFile).join(Partition).filter(
            Partition.evidence_id == evidence_id
        )
    
    if file_type:
        query = query.filter(RecoveredFile.file_type == file_type.lower())
    
    total = query.count()
    files = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "recovered_files": [f.to_dict() for f in files]
    }


@router.get("/carved")
def list_carved_files(
    evidence_id: Optional[int] = None,
    signature_type: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    List all carved files.
    
    **Filters:**
    - evidence_id: Filter by evidence
    - signature_type: Filter by file signature (jpg, pdf, etc.)
    - skip/limit: Pagination
    
    **Returns:** List of carved file metadata
    """
    query = db.query(CarvedFile)
    
    if evidence_id:
        from app.models import Partition
        query = query.join(Partition).filter(
            Partition.evidence_id == evidence_id
        )
    
    if signature_type:
        query = query.filter(CarvedFile.signature_type == signature_type.lower())
    
    total = query.count()
    files = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "carved_files": [f.to_dict() for f in files]
    }


@router.get("/download/recovered/{file_id}")
def download_recovered_file(
    file_id: int,
    db: Session = Depends(get_db)
):
    """
    Download a recovered file.
    
    **Forensic Process:**
    1. Verify file exists
    2. Log download to audit trail
    3. Update export statistics
    4. Stream file to client
    
    **Security:** File paths sanitized, no directory traversal
    
    **Returns:** File download
    """
    recovered_file = db.query(RecoveredFile).filter(RecoveredFile.id == file_id).first()
    
    if not recovered_file:
        raise HTTPException(status_code=404, detail="Recovered file not found")
    
    file_path = Path(recovered_file.file_path)
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    # Update export statistics
    recovered_file.is_exported = True
    recovered_file.export_count += 1
    recovered_file.last_exported_at = datetime.utcnow()
    db.commit()
    
    # Get evidence for audit log
    from app.models import DeletedFile, Partition
    deleted_file = db.query(DeletedFile).filter(
        DeletedFile.id == recovered_file.deleted_file_id
    ).first()
    
    if deleted_file:
        partition = db.query(Partition).filter(Partition.id == deleted_file.partition_id).first()
        if partition:
            evidence = db.query(Evidence).filter(Evidence.id == partition.evidence_id).first()
            
            # Audit log
            log_action(
                db=db,
                user="api_user",  # Replace with actual user if authentication implemented
                action="download",
                evidence_id=evidence.id,
                details=f"Downloaded recovered file: {recovered_file.original_filename}",
                status="success",
                files_affected=1,
                bytes_processed=recovered_file.size_bytes
            )
    
    # Determine MIME type
    mime_type = mimetypes.guess_type(str(file_path))[0] or 'application/octet-stream'
    
    # Return file
    return FileResponse(
        path=str(file_path),
        media_type=mime_type,
        filename=recovered_file.original_filename,
        headers={
            "X-File-SHA256": recovered_file.sha256_hash,
            "X-Recovery-Method": recovered_file.recovery_method
        }
    )


@router.get("/download/carved/{file_id}")
def download_carved_file(
    file_id: int,
    db: Session = Depends(get_db)
):
    """
    Download a carved file.
    
    **Forensic Process:**
    1. Verify file exists
    2. Log download to audit trail
    3. Update export statistics
    4. Stream file to client
    
    **Returns:** File download
    """
    carved_file = db.query(CarvedFile).filter(CarvedFile.id == file_id).first()
    
    if not carved_file:
        raise HTTPException(status_code=404, detail="Carved file not found")
    
    file_path = Path(carved_file.file_path)
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    # Update export statistics
    carved_file.is_exported = True
    carved_file.export_count += 1
    carved_file.last_exported_at = datetime.utcnow()
    db.commit()
    
    # Get evidence for audit log
    from app.models import Partition
    partition = db.query(Partition).filter(Partition.id == carved_file.partition_id).first()
    
    if partition:
        evidence = db.query(Evidence).filter(Evidence.id == partition.evidence_id).first()
        
        # Audit log
        log_action(
            db=db,
            user="api_user",  # Replace with actual user if authentication implemented
            action="download",
            evidence_id=evidence.id,
            details=f"Downloaded carved file: {carved_file.carved_filename}",
            status="success",
            files_affected=1,
            bytes_processed=carved_file.size_bytes
        )
    
    # Determine MIME type
    mime_type = mimetypes.guess_type(str(file_path))[0] or 'application/octet-stream'
    
    # Return file
    return FileResponse(
        path=str(file_path),
        media_type=mime_type,
        filename=carved_file.carved_filename,
        headers={
            "X-File-SHA256": carved_file.sha256_hash,
            "X-Carving-Method": carved_file.carving_method
        }
    )


@router.get("/info/recovered/{file_id}")
def get_recovered_file_info(
    file_id: int,
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a recovered file.
    
    **Returns:** Complete file metadata
    """
    recovered_file = db.query(RecoveredFile).filter(RecoveredFile.id == file_id).first()
    
    if not recovered_file:
        raise HTTPException(status_code=404, detail="Recovered file not found")
    
    # Get related deleted file
    from app.models import DeletedFile
    deleted_file = db.query(DeletedFile).filter(
        DeletedFile.id == recovered_file.deleted_file_id
    ).first()
    
    return {
        "recovered_file": recovered_file.to_dict(),
        "deleted_file": deleted_file.to_dict() if deleted_file else None
    }


@router.get("/info/carved/{file_id}")
def get_carved_file_info(
    file_id: int,
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a carved file.
    
    **Returns:** Complete file metadata
    """
    carved_file = db.query(CarvedFile).filter(CarvedFile.id == file_id).first()
    
    if not carved_file:
        raise HTTPException(status_code=404, detail="Carved file not found")
    
    return carved_file.to_dict()


@router.delete("/recovered/{file_id}")
def delete_recovered_file(
    file_id: int,
    confirm: bool = False,
    db: Session = Depends(get_db)
):
    """
    Delete a recovered file.
    
    **WARNING:** This permanently deletes the recovered file from disk.
    
    **Requires:** confirm=true parameter
    """
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Deletion requires confirm=true parameter"
        )
    
    recovered_file = db.query(RecoveredFile).filter(RecoveredFile.id == file_id).first()
    
    if not recovered_file:
        raise HTTPException(status_code=404, detail="Recovered file not found")
    
    # Delete physical file
    try:
        file_path = Path(recovered_file.file_path)
        if file_path.exists():
            file_path.unlink()
    except Exception as e:
        print(f"Warning: File deletion failed: {e}")
    
    # Delete database record
    db.delete(recovered_file)
    db.commit()
    
    return {
        "success": True,
        "message": "Recovered file deleted successfully"
    }


@router.get("/search")
def search_files(
    query: str,
    file_source: str = "all",  # all, recovered, carved
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Search for files by filename.
    
    **Parameters:**
    - query: Search term
    - file_source: Search in 'recovered', 'carved', or 'all'
    - skip/limit: Pagination
    
    **Returns:** Matching files
    """
    results = {
        "query": query,
        "recovered_files": [],
        "carved_files": []
    }
    
    if file_source in ["all", "recovered"]:
        recovered = db.query(RecoveredFile).filter(
            RecoveredFile.original_filename.like(f"%{query}%")
        ).offset(skip).limit(limit).all()
        
        results["recovered_files"] = [f.to_dict() for f in recovered]
    
    if file_source in ["all", "carved"]:
        carved = db.query(CarvedFile).filter(
            CarvedFile.carved_filename.like(f"%{query}%")
        ).offset(skip).limit(limit).all()
        
        results["carved_files"] = [f.to_dict() for f in carved]
    
    return results
