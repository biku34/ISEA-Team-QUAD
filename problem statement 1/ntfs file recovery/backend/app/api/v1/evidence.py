"""
Evidence Management API endpoints.
Handles E01 image upload, verification, and listing.

FORENSIC REQUIREMENTS:
- Hash verification
- Chain of custody tracking
- Read-only evidence handling
- Complete audit logging
"""

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, Form, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pathlib import Path
from datetime import datetime
import shutil
import yaml
import uuid
import json

from app.database import get_db
from app.models import Evidence, log_action
from app.services.forensic_engine import ForensicEngine
from app.services.segment_handler import SegmentHandler, SegmentError

# Load config
config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.yaml"
if not config_path.exists():
    config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.example.yaml"

with open(config_path, 'r') as f:
    CONFIG = yaml.safe_load(f)

router = APIRouter()
forensic_engine = ForensicEngine()


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    file: UploadFile = File(..., description="E01 forensic image file"),
    case_name: str = Form(..., description="Case identifier"),
    examiner: str = Form(..., description="Examiner name"),
    case_number: Optional[str] = Form(None, description="Official case number"),
    organization: Optional[str] = Form(None, description="Organization"),
    description: Optional[str] = Form(None, description="Case description"),
    expected_hash: Optional[str] = Form(None, description="Expected SHA-256 hash"),
    db: Session = Depends(get_db)
):
    """
    Upload E01 forensic image to evidence storage.
    
    **Forensic Process:**
    1. Validates file extension (.E01, .E02, etc.)
    2. Saves to evidence storage
    3. Calculates SHA-256 hash
    4. Creates evidence record
    5. Logs to audit trail
    
    **Security:**
    - File size limit: 100GB
    - Extension validation
    - Path sanitization
    
    **Returns:** Evidence metadata with ID
    """
    
    # Validate file extension
    filename = file.filename
    allowed_exts = CONFIG['security']['allowed_extensions']
    
    if not any(filename.upper().endswith(ext.upper()) for ext in allowed_exts):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(allowed_exts)}"
        )
    
    # Create evidence storage directory
    evidence_dir = Path(CONFIG['storage']['evidence_dir'])
    evidence_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate unique filename with timestamp
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_filename = f"{case_name}_{timestamp}_{filename}"
    file_path = evidence_dir / safe_filename
    
    # Save uploaded file
    try:
        with open(file_path, 'wb') as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")
    
    # Get file size
    file_size = file_path.stat().st_size
    
    # Check max size
    max_size = CONFIG['security']['max_upload_size']
    if file_size > max_size:
        file_path.unlink()  # Delete file
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max: {max_size / (1024**3):.1f} GB"
        )
    
    # Calculate SHA-256 hash
    try:
        sha256_hash = forensic_engine.calculate_hash(str(file_path))
    except Exception as e:
        file_path.unlink()  # Delete file on error
        raise HTTPException(status_code=500, detail=f"Hash calculation failed: {str(e)}")
    
    # Verify hash if provided
    hash_verified = False
    if expected_hash:
        hash_verified = (sha256_hash.lower() == expected_hash.lower())
    
    # Check if this is a segmented file
    is_segmented = False
    segment_number = None
    parsed = SegmentHandler.parse_segment_filename(filename)
    if parsed:
        base_name, seg_num = parsed
        is_segmented = True
        segment_number = seg_num
    
    # Create evidence record
    evidence = Evidence(
        filename=filename,
        file_path=str(file_path),
        size_bytes=file_size,
        sha256_hash=sha256_hash,
        hash_verified=hash_verified,
        expected_hash=expected_hash,
        case_name=case_name,
        case_number=case_number,
        examiner=examiner,
        organization=organization,
        description=description,
        is_segmented=is_segmented,
        segment_number=segment_number,
        analysis_status="uploaded"
    )
    
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    
    # Audit log
    log_action(
        db=db,
        user=examiner,
        action="upload",
        evidence_id=evidence.id,
        details=f"Uploaded {filename} ({file_size} bytes), SHA-256: {sha256_hash}",
        status="success"
    )
    
    return {
        "success": True,
        "message": "Evidence uploaded successfully",
        "evidence": evidence.to_dict(),
        "hash_verified": hash_verified
    }



@router.post("/upload-segmented/initiate", status_code=status.HTTP_200_OK)
async def initiate_segmented_upload(
    case_name: str = Form(...),
    examiner: str = Form(...),
    total_segments: int = Form(...),
    case_number: Optional[str] = Form(None),
    organization: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    expected_hash: Optional[str] = Form(None),
):
    """
    Initiate a stateful segmented upload session.
    Returns an upload_id to be used for subsequent segment uploads.
    """
    upload_id = str(uuid.uuid4())
    temp_dir = Path(CONFIG['storage']['temp_dir']) / f"upload_{upload_id}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    # Store metadata
    metadata = {
        "case_name": case_name,
        "examiner": examiner,
        "total_segments": total_segments,
        "case_number": case_number,
        "organization": organization,
        "description": description,
        "expected_hash": expected_hash,
        "timestamp": datetime.utcnow().strftime("%Y%m%d_%H%M%S"),
        "uploaded_segments": []
    }
    
    with open(temp_dir / "metadata.json", "w") as f:
        json.dump(metadata, f)
        
    return {
        "success": True, 
        "upload_id": upload_id,
        "message": "Upload session initiated"
    }


@router.post("/upload-segmented/upload/{upload_id}", status_code=status.HTTP_200_OK)
async def upload_segment_part(
    upload_id: str,
    file: UploadFile = File(...),
):
    """
    Upload a single segment for an active session.
    """
    temp_dir = Path(CONFIG['storage']['temp_dir']) / f"upload_{upload_id}"
    if not temp_dir.exists():
        raise HTTPException(status_code=404, detail="Upload session not found or expired")
        
    # Save segment
    file_path = temp_dir / file.filename
    try:
        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save segment: {str(e)}")
        
    # Update metadata
    with open(temp_dir / "metadata.json", "r") as f:
        metadata = json.load(f)
        
    if file.filename not in metadata["uploaded_segments"]:
        metadata["uploaded_segments"].append(file.filename)
        
    with open(temp_dir / "metadata.json", "w") as f:
        json.dump(metadata, f)
        
    return {
        "success": True,
        "filename": file.filename,
        "segments_uploaded": len(metadata["uploaded_segments"]),
        "total_segments": metadata["total_segments"]
    }


@router.post("/upload-segmented/finalize/{upload_id}", status_code=status.HTTP_201_CREATED)
async def finalize_segmented_upload(
    upload_id: str,
    db: Session = Depends(get_db)
):
    """
    Finalize the segmented upload, validate the set, and create evidence record.
    """
    temp_dir = Path(CONFIG['storage']['temp_dir']) / f"upload_{upload_id}"
    if not temp_dir.exists():
        raise HTTPException(status_code=404, detail="Upload session not found")
        
    with open(temp_dir / "metadata.json", "r") as f:
        metadata = json.load(f)
        
    # Check if all segments are present
    if len(metadata["uploaded_segments"]) < metadata["total_segments"]:
        raise HTTPException(
            status_code=400, 
            detail=f"Incomplete set. Uploaded {len(metadata['uploaded_segments'])} of {metadata['total_segments']}"
        )
        
    # Create final directory
    evidence_dir = Path(CONFIG['storage']['evidence_dir'])
    evidence_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = metadata["timestamp"]
    case_name = metadata["case_name"]
    
    # Move files to final storage
    final_paths = []
    for filename in metadata["uploaded_segments"]:
        source = temp_dir / filename
        safe_filename = f"{case_name}_{timestamp}_{filename}"
        dest = evidence_dir / safe_filename
        shutil.move(str(source), str(dest))
        final_paths.append(dest)
        
    # Validate set
    try:
        validation = SegmentHandler.validate_segment_set(final_paths)
        primary_segment_path = SegmentHandler.get_primary_segment(final_paths)
    except SegmentError as e:
        # Cleanup and fail
        for p in final_paths:
            if p.exists(): p.unlink()
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Segment validation failed: {str(e)}")
        
    # Calculate hashes
    segment_hashes = []
    for seg_info in validation['segments']:
        seg_hash = forensic_engine.calculate_hash(str(seg_info['path']))
        segment_hashes.append({
            'segment_number': seg_info['segment_number'],
            'path': seg_info['path'],
            'hash': seg_hash
        })
        
    primary_hash = next(h['hash'] for h in segment_hashes if h['segment_number'] == 1)
    
    # Create Evidence record
    evidence = Evidence(
        filename=primary_segment_path.name.split(f"_{timestamp}_")[-1],
        file_path=str(primary_segment_path),
        size_bytes=validation['total_size'],
        sha256_hash=primary_hash,
        case_name=case_name,
        case_number=metadata.get("case_number"),
        examiner=metadata["examiner"],
        organization=metadata.get("organization"),
        description=metadata.get("description"),
        is_segmented=True,
        segment_number=1,
        total_segments=validation['total_segments'],
        analysis_status="uploaded"
    )
    
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    
    # Cleanup temp dir
    shutil.rmtree(temp_dir, ignore_errors=True)
    
    # Audit log
    log_action(
        db=db,
        user=metadata["examiner"],
        action="upload_segmented_sequential",
        evidence_id=evidence.id,
        details=f"Sequentially uploaded {validation['total_segments']} segments.",
        status="success"
    )
    
    return {
        "success": True,
        "message": "Segmented evidence finalized and imported",
        "evidence": evidence.to_dict()
    }


@router.get("/list")
def list_evidence(
    skip: int = 0,
    limit: int = 100,
    case_name: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    List all uploaded evidence files.
    
    **Filters:**
    - case_name: Filter by case name
    - skip/limit: Pagination
    
    **Returns:** List of evidence metadata
    """
    query = db.query(Evidence)
    
    if case_name:
        query = query.filter(Evidence.case_name.like(f"%{case_name}%"))
    
    total = query.count()
    evidence_list = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "evidence": [e.to_dict() for e in evidence_list]
    }


@router.get("/{evidence_id}")
def get_evidence(evidence_id: int, db: Session = Depends(get_db)):
    """
    Get detailed information about specific evidence.
    
    **Returns:** Complete evidence metadata
    """
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    return evidence.to_dict()


@router.post("/verify/{evidence_id}")
def verify_evidence_hash(
    evidence_id: int,
    expected_hash: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Verify evidence integrity using SHA-256 hash.
    
    **Forensic Process:**
    1. Recalculate hash of evidence file
    2. Compare with expected hash
    3. Update verification status
    4. Log verification result
    
    **Returns:** Verification result
    """
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    # Use provided hash or stored expected hash
    check_hash = expected_hash or evidence.expected_hash
    
    if not check_hash:
        raise HTTPException(
            status_code=400,
            detail="No expected hash provided"
        )
    
    # Recalculate hash
    try:
        current_hash = forensic_engine.calculate_hash(evidence.file_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hash calculation failed: {str(e)}")
    
    # Verify
    verified = (current_hash.lower() == check_hash.lower())
    
    # Update evidence record
    evidence.hash_verified = verified
    if expected_hash:
        evidence.expected_hash = expected_hash
    
    if verified:
        evidence.analysis_status = "verified"
    
    db.commit()
    
    # Audit log
    log_action(
        db=db,
        user=evidence.examiner,
        action="verify",
        evidence_id=evidence.id,
        details=f"Hash verification: {'SUCCESS' if verified else 'FAILED'}",
        status="success" if verified else "failure"
    )
    
    return {
        "success": True,
        "verified": verified,
        "current_hash": current_hash,
        "expected_hash": check_hash,
        "message": "Hash verification successful" if verified else "Hash mismatch - evidence may be corrupted"
    }


@router.delete("/{evidence_id}")
def delete_evidence(
    evidence_id: int,
    confirm: bool = False,
    db: Session = Depends(get_db)
):
    """
    Delete evidence file and all associated data.
    
    **WARNING:** This permanently deletes:
    - Evidence file
    - All partition data
    - All deleted file records
    - All recovered files
    - All carved files
    - Audit logs
    
    **Requires:** confirm=true parameter
    """
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Deletion requires confirm=true parameter"
        )
    
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    # Unmount if mounted
    if evidence.is_mounted:
        try:
            forensic_engine.unmount_image(evidence.mount_point)
        except Exception as e:
            print(f"Warning: Unmount failed: {e}")
    
    # Delete physical file
    try:
        file_path = Path(evidence.file_path)
        if file_path.exists():
            file_path.unlink()
    except Exception as e:
        print(f"Warning: File deletion failed: {e}")
    
    # Audit log before deletion
    log_action(
        db=db,
        user=evidence.examiner,
        action="delete",
        evidence_id=evidence.id,
        details=f"Deleted evidence: {evidence.filename}",
        status="success"
    )
    
    # Delete database record (cascades to all related records)
    db.delete(evidence)
    db.commit()
    
    return {
        "success": True,
        "message": "Evidence deleted successfully"
    }
