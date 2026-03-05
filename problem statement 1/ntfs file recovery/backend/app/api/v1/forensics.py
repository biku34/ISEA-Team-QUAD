"""
Forensic Analysis API endpoints.
Timeline generation, audit logging, and reporting.

FORENSIC STANDARDS:
- MACB timeline reconstruction
- Complete chain of custody reporting
- Statistical analysis
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path
import yaml

from app.database import get_db
from app.models import Evidence, Partition, DeletedFile, RecoveredFile, CarvedFile, AuditLog

# Load config
config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.yaml"
if not config_path.exists():
    config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.example.yaml"

with open(config_path, 'r') as f:
    CONFIG = yaml.safe_load(f)

router = APIRouter()


@router.get("/timeline/{evidence_id}")
def get_timeline(
    evidence_id: int,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = 1000,
    skip: int = 0,
    db: Session = Depends(get_db)
):
    """
    Generate MACB (Modified, Accessed, Changed, Birth) timeline for an evidence source.
    
    **Forensic Utility:**
    - Reconstructs sequence of events
    - Correlates file activities
    - Identifies temporal patterns
    """
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    # This is a simplified timeline generation associated with DeletedFiles
    # In a full forensic suite, this would include all file system activity.
    # Here we aggregate timestamps from deleted files.
    
    # We'll fetch deleted files and transform them into timeline events
    query = db.query(DeletedFile).join(Partition).filter(Partition.evidence_id == evidence_id)
    
    files = query.all()
    
    timeline_events = []
    
    for f in files:
        # Create events for each timestamp if it exists
        if f.time_modified:
            timeline_events.append({
                "timestamp": f.time_modified,
                "type": "MODIFIED",
                "file": f.filename,
                "inode": f.inode,
                "description": "File content modified"
            })
        if f.time_accessed:
            timeline_events.append({
                "timestamp": f.time_accessed,
                "type": "ACCESSED",
                "file": f.filename,
                "inode": f.inode,
                "description": "File accessed/read"
            })
        if f.time_changed:
            timeline_events.append({
                "timestamp": f.time_changed,
                "type": "CHANGED",
                "file": f.filename,
                "inode": f.inode,
                "description": "Metadata changed"
            })
        if f.time_birth:
            timeline_events.append({
                "timestamp": f.time_birth,
                "type": "BIRTH",
                "file": f.filename,
                "inode": f.inode,
                "description": "File created"
            })
            
    # Sort by timestamp
    timeline_events.sort(key=lambda x: x["timestamp"], reverse=True)
    
    # Filter by date range if provided implies filtering the list
    if start_date:
        timeline_events = [e for e in timeline_events if e["timestamp"] >= start_date]
    if end_date:
        timeline_events = [e for e in timeline_events if e["timestamp"] <= end_date]
        
    total_events = len(timeline_events)
    paginated_events = timeline_events[skip : skip + limit]
    
    return {
        "evidence_id": evidence_id,
        "total_events": total_events,
        "events": paginated_events
    }


@router.get("/metadata/{file_id}")
def get_file_metadata(
    file_id: int,
    db: Session = Depends(get_db)
):
    """
    Get detailed forensic metadata for a specific deleted file (by ID).
    Includes MFT attributes and flags.
    """
    f = db.query(DeletedFile).filter(DeletedFile.id == file_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="File not found")
        
    return {
        "id": f.id,
        "filename": f.filename,
        "inode": f.inode,
        "partition_id": f.partition_id,
        "size": f.size_bytes,
        "timestamps": {
            "created": f.time_birth,
            "modified": f.time_modified,
            "accessed": f.time_accessed,
            "changed": f.time_changed
        },
        "mft_flags": f.mft_flags,
        "mft_entry": f.mft_entry,
        "is_recovered": f.is_recovered
    }


@router.get("/audit/log")
def get_audit_log(
    evidence_id: Optional[int] = None,
    user: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 100,
    skip: int = 0,
    db: Session = Depends(get_db)
):
    """
    Retrieve forensic audit logs.
    Chain of custody requires valid, immutable logs of all actions.
    """
    query = db.query(AuditLog)
    
    if evidence_id:
        query = query.filter(AuditLog.evidence_id == evidence_id)
    if user:
        query = query.filter(AuditLog.user == user)
    if action:
        query = query.filter(AuditLog.action == action)
        
    # Order by timestamp descending
    query = query.order_by(AuditLog.timestamp.desc())
    
    total = query.count()
    logs = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp,
                "user": log.user,
                "action": log.action,
                "evidence_id": log.evidence_id,
                "details": log.details,
                "status": log.status,
                "ip_address": log.ip_address
            }
            for log in logs
        ]
    }


@router.post("/report/generate")
def generate_report(
    evidence_id: int,
    report_type: str = Query(..., regex="^(pdf|json|html)$"),
    include_timeline: bool = True,
    include_audit: bool = True,
    db: Session = Depends(get_db)
):
    """
    Generate a forensic report for a specific case/evidence.
    Supported formats: JSON (implemented), PDF/HTML (placeholders).
    """
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    report_data = {
        "case_info": {
            "case_name": evidence.case_name,
            "examiner": evidence.examiner,
            "organization": evidence.organization,
            "generated_at": datetime.utcnow().isoformat()
        },
        "evidence_info": evidence.to_dict(),
        "stats": _get_stats(db, evidence_id)
    }

    if include_audit:
        audits = db.query(AuditLog).filter(Evidence.id == evidence_id).all()
        report_data["audit_log"] = [
            {
                "timestamp": a.timestamp.isoformat(),
                "user": a.user,
                "action": a.action,
                "details": a.details
            } for a in audits
        ]
        
    if report_type == "json":
        return report_data
    else:
        # PDF/HTML generation would go here (using reportlab or jinja2)
        # For now, we return a message or the data structure with a note
        return {
            "message": f"{report_type.upper()} report generation not yet implemented. Returning data.",
            "data": report_data
        }


@router.get("/statistics/{evidence_id}")
def get_statistics(
    evidence_id: int,
    db: Session = Depends(get_db)
):
    """
    Get statistical summary of the forensic analysis.
    """
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
        
    return _get_stats(db, evidence_id)


def _get_stats(db: Session, evidence_id: int) -> Dict[str, Any]:
    """Helper to calculate statistics"""
    
    partition_count = db.query(Partition).filter(Partition.evidence_id == evidence_id).count()
    
    deleted_files_count = db.query(DeletedFile).join(Partition).filter(
        Partition.evidence_id == evidence_id
    ).count()
    
    recovered_files_count = db.query(RecoveredFile).join(DeletedFile).join(Partition).filter(
        Partition.evidence_id == evidence_id
    ).count()
    
    total_recovered_size = db.query(func.sum(RecoveredFile.size_bytes)).join(DeletedFile).join(Partition).filter(
        Partition.evidence_id == evidence_id
    ).scalar() or 0
    
    carved_files_count = db.query(CarvedFile).join(Partition).filter(
        Partition.evidence_id == evidence_id
    ).count()
    
    return {
        "partitions_found": partition_count,
        "deleted_files_enumerated": deleted_files_count,
        "files_recovered": recovered_files_count,
        "total_recovered_bytes": total_recovered_size,
        "files_carved": carved_files_count
    }
