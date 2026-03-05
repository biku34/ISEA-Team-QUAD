"""
Scanning API endpoints.
Partition detection and deleted file enumeration using SleuthKit.

FORENSIC OPERATIONS:
- mmls: Partition table analysis
- fls: NTFS Master File Table scanning
- MFT metadata extraction
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import Optional
from pathlib import Path
import yaml

import logging
from app.database import get_db
from app.models import Evidence, Partition, DeletedFile, log_action
from app.services.forensic_engine import ForensicEngine, MountError, ScanError

logger = logging.getLogger(__name__)

# Load config
config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.yaml"
if not config_path.exists():
    config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.example.yaml"

with open(config_path, 'r') as f:
    CONFIG = yaml.safe_load(f)

router = APIRouter()
forensic_engine = ForensicEngine()


@router.post("/partitions")
def scan_partitions(
    evidence_id: int,
    db: Session = Depends(get_db)
):
    """
    Detect and catalog partitions in evidence image using mmls.
    
    **Forensic Process:**
    1. Mount E01 image (read-only)
    2. Run mmls to detect partition table
    3. Identify NTFS partitions
    4. Store partition metadata
    5. Unmount image
    
    **Returns:** List of detected partitions
    """
    # Get evidence
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    # Check if already scanned
    existing_partitions = db.query(Partition).filter(Partition.evidence_id == evidence_id).count()
    if existing_partitions > 0:
        raise HTTPException(
            status_code=409,
            detail="Partitions already scanned. Delete existing partitions first."
        )
    
    # Mount image
    mount_point = None
    try:
        mount_point = forensic_engine.mount_image(evidence.file_path, evidence_id)
        
        # Update evidence record
        evidence.is_mounted = True
        evidence.mount_point = mount_point
        db.commit()
        
        # Detect partitions
        partition_list = forensic_engine.detect_partitions(mount_point)
        
        # Store partitions in database
        created_partitions = []
        
        for i, part_data in enumerate(partition_list):
            partition = Partition(
                evidence_id=evidence_id,
                partition_number=i,
                slot=part_data.get('slot', i),
                start_offset=part_data['start_offset'],
                end_offset=part_data.get('end_offset'),
                length_sectors=part_data['length_sectors'],
                size_bytes=part_data['size_bytes'],
                filesystem_type=part_data['filesystem_type'],
                description=part_data.get('description', ''),
                is_ntfs=1 if part_data['filesystem_type'] == 'NTFS' else 0,
                scan_status='detected'
            )
            
            db.add(partition)
            created_partitions.append(partition)
        
        db.commit()
        
        # Update evidence status
        evidence.partition_scan_completed = True
        evidence.analysis_status = "partitions_scanned"
        db.commit()
        
        # Audit log
        log_action(
            db=db,
            user=evidence.examiner,
            action="scan_partitions",
            evidence_id=evidence_id,
            details=f"Detected {len(partition_list)} partitions",
            status="success",
            command=f"mmls {mount_point}/ewf1"
        )
        
        # Unmount
        forensic_engine.unmount_image(mount_point)
        evidence.is_mounted = False
        evidence.mount_point = None
        db.commit()
        
        return {
            "success": True,
            "message": f"Detected {len(partition_list)} partitions",
            "partitions": [p.to_dict() for p in created_partitions]
        }
    
    except MountError as e:
        log_action(
            db=db,
            user=evidence.examiner,
            action="scan_partitions",
            evidence_id=evidence_id,
            details=f"Mount failed: {str(e)}",
            status="failure"
        )
        raise HTTPException(status_code=500, detail=f"Mount error: {str(e)}")
    
    except ScanError as e:
        log_action(
            db=db,
            user=evidence.examiner,
            action="scan_partitions",
            evidence_id=evidence_id,
            details=f"Scan failed: {str(e)}",
            status="failure"
        )
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
    
    finally:
        # Ensure unmount
        if mount_point:
            try:
                forensic_engine.unmount_image(mount_point)
                evidence.is_mounted = False
                evidence.mount_point = None
                db.commit()
            except:
                pass


def background_scan_deleted(evidence_id: int, partition_id: int):
    """
    Background worker for scanning deleted files.
    """
    from app.database import SessionLocal
    db = SessionLocal()
    
    # Get evidence and partition
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    partition = db.query(Partition).filter(Partition.id == partition_id).first()
    
    if not evidence or not partition:
        db.close()
        return

    mount_point = None
    try:
        mount_point = forensic_engine.mount_image(evidence.file_path, evidence_id)
        
        # Update statuses
        partition.scan_status = "scanning"
        db.commit()
        
        # Scan for deleted files
        deleted_files_data = forensic_engine.scan_deleted_files(
            mount_point,
            partition.start_offset
        )
        
        logger.info(f"Scan complete. Found {len(deleted_files_data)} raw entries for partition {partition_id}")
        
        # Store deleted files
        count = 0
        for file_data in deleted_files_data:
            # Skip entries that aren't actually files or are just dot entries
            if not file_data.get('filename') or file_data['filename'] in ['.', '..']:
                continue
                
            deleted_file = DeletedFile(
                partition_id=partition_id,
                inode=file_data['inode'],
                filename=file_data['filename'],
                size_bytes=file_data['size_bytes'],
                file_type=file_data.get('file_type'),
                time_modified=file_data.get('time_modified'),
                time_accessed=file_data.get('time_accessed'),
                time_changed=file_data.get('time_changed'),
                time_birth=file_data.get('time_birth'),
                mft_entry=file_data['inode'],
                mft_flags=file_data.get('mft_flags', 'r/r'),
                is_deleted=True,
                is_recoverable=True,
                recovery_status='not_attempted'
            )
            db.add(deleted_file)
            count += 1
            
            # Commit in batches of 1000 for efficiency
            if count % 1000 == 0:
                db.commit()
        
        db.commit()
        
        # Update status
        partition.scan_status = "completed"
        partition.deleted_file_count = count
        
        # Update evidence status
        evidence.deleted_scan_completed = True
        evidence.analysis_status = "deleted_scanned"
        db.commit()
        
        # Audit log
        log_action(
            db=db,
            user=evidence.examiner,
            action="scan_deleted",
            evidence_id=evidence_id,
            details=f"Background scan found {count} deleted files",
            status="success"
        )
        
    except Exception as e:
        logger.error(f"Background scan failed: {str(e)}")
        partition.scan_status = "error"
        partition.scan_error = str(e)
        db.commit()
    finally:
        if mount_point:
            forensic_engine.unmount_image(mount_point)
        db.close()


@router.post("/deleted", status_code=status.HTTP_202_ACCEPTED)
def scan_deleted_files(
    evidence_id: int,
    partition_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Scan NTFS partition for deleted files as a background task.
    """
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    partition = db.query(Partition).filter(Partition.id == partition_id).first()
    
    if not evidence or not partition:
        raise HTTPException(status_code=404, detail="Evidence or Partition not found")
    
    if partition.scan_status == "scanning":
        raise HTTPException(status_code=409, detail="Scan already in progress")

    # Start background task
    partition.scan_status = "scanning"
    db.commit()
    
    background_tasks.add_task(background_scan_deleted, evidence_id, partition_id)
    
    return {
        "success": True,
        "message": "Deleted file scan initiated in background",
        "partition_id": partition_id
    }


@router.get("/partitions/{evidence_id}")
def get_partitions(
    evidence_id: int,
    ntfs_only: bool = False,
    db: Session = Depends(get_db)
):
    """
    Get list of detected partitions for evidence.
    
    **Filters:**
    - ntfs_only: Only return NTFS partitions
    
    **Returns:** List of partition metadata
    """
    query = db.query(Partition).filter(Partition.evidence_id == evidence_id)
    
    if ntfs_only:
        query = query.filter(Partition.is_ntfs == 1)
    
    partitions = query.all()
    
    return {
        "evidence_id": evidence_id,
        "total_partitions": len(partitions),
        "partitions": [p.to_dict() for p in partitions]
    }


@router.get("/deleted/{partition_id}")
def get_deleted_files(
    partition_id: int,
    skip: int = 0,
    limit: int = 100,
    file_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Get list of deleted files in a partition.
    
    **Filters:**
    - file_type: Filter by file extension (e.g., 'docx', 'jpg')
    - skip/limit: Pagination
    
    **Returns:** List of deleted file metadata with MACB timestamps
    """
    query = db.query(DeletedFile).filter(DeletedFile.partition_id == partition_id)
    
    if file_type:
        query = query.filter(DeletedFile.file_type == file_type.lower())
    
    total = query.count()
    deleted_files = query.offset(skip).limit(limit).all()
    
    return {
        "partition_id": partition_id,
        "total": total,
        "skip": skip,
        "limit": limit,
        "deleted_files": [df.to_dict() for df in deleted_files]
    }


@router.get("/hierarchy/{partition_id}")
def get_hierarchy(
    partition_id: int,
    db: Session = Depends(get_db)
):
    """
    Get the complete file structure hierarchy for a partition.
    Returns a flat list of all files with paths.
    """
    partition = db.query(Partition).filter(Partition.id == partition_id).first()
    if not partition:
        raise HTTPException(status_code=404, detail="Partition not found")
        
    evidence = db.query(Evidence).filter(Evidence.id == partition.evidence_id).first()
    
    mount_point = None
    try:
        mount_point = forensic_engine.mount_image(evidence.file_path, evidence.id)
        files = forensic_engine.list_all_files(mount_point, partition.start_offset)
        
        return {
            "success": True,
            "partition_id": partition_id,
            "total_files": len(files),
            "files": files
        }
    except Exception as e:
        logger.error(f"Failed to get hierarchy: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if mount_point:
            forensic_engine.unmount_image(mount_point)


@router.get("/ls/{partition_id}")
def get_ls(
    partition_id: int,
    inode: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """
    List contents of a specific directory by inode.
    If inode is not provided, lists the root directory.
    """
    partition = db.query(Partition).filter(Partition.id == partition_id).first()
    if not partition:
        raise HTTPException(status_code=404, detail="Partition not found")
        
    evidence = db.query(Evidence).filter(Evidence.id == partition.evidence_id).first()
    
    mount_point = None
    try:
        mount_point = forensic_engine.mount_image(evidence.file_path, evidence.id)
        files = forensic_engine.list_directory(mount_point, partition.start_offset, inode)
        
        return {
            "success": True,
            "partition_id": partition_id,
            "directory_inode": inode or "root",
            "total_items": len(files),
            "items": files
        }
    except Exception as e:
        logger.error(f"Failed to list directory: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if mount_point:
            forensic_engine.unmount_image(mount_point)
