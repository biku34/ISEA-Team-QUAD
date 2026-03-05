"""
File Recovery API endpoints.
Recover deleted files using icat and carve files using Scalpel.

FORENSIC OPERATIONS:
- icat: MFT-based file recovery by inode
- scalpel: Signature-based file carving from unallocated space
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import Optional, Tuple, List
from pydantic import BaseModel

class BatchRecoverRequest(BaseModel):
    evidence_id: int
    file_ids: List[int]
from pathlib import Path
from datetime import datetime
import uuid
import yaml
from loguru import logger

from app.database import get_db
from app.models import Evidence, Partition, DeletedFile, RecoveredFile, CarvedFile, CarvingSession, log_action
from app.services.forensic_engine import ForensicEngine, RecoveryError

# Load config
config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.yaml"
if not config_path.exists():
    config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.example.yaml"

with open(config_path, 'r') as f:
    CONFIG = yaml.safe_load(f)

router = APIRouter()
forensic_engine = ForensicEngine()


@router.post("/recover/{deleted_file_id}")
def recover_file(
    deleted_file_id: int,
    db: Session = Depends(get_db)
):
    """
    Recover a specific deleted file using icat.
    
    **Forensic Process:**
    1. Lookup deleted file metadata
    2. Mount evidence image
    3. Use icat to extract file data by inode
    4. Calculate SHA-256 hash
    5. Store recovered file
    6. Update recovery status
    
    **Returns:** Recovered file metadata
    """
    # Get deleted file
    deleted_file = db.query(DeletedFile).filter(DeletedFile.id == deleted_file_id).first()
    
    if not deleted_file:
        raise HTTPException(status_code=404, detail="Deleted file not found")
    
    # Check if already recovered
    existing_recovery = db.query(RecoveredFile).filter(
        RecoveredFile.deleted_file_id == deleted_file_id
    ).first()
    
    if existing_recovery:
        raise HTTPException(
            status_code=409,
            detail="File already recovered",
            headers={"X-Recovered-File-ID": str(existing_recovery.id)}
        )
    
    # Get partition and evidence
    partition = db.query(Partition).filter(Partition.id == deleted_file.partition_id).first()
    evidence = db.query(Evidence).filter(Evidence.id == partition.evidence_id).first()
    
    # Create unique filename
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    file_ext = deleted_file.file_type or "bin"
    recovered_filename = f"{timestamp}_{deleted_file.inode}.{file_ext}"
    
    output_path = Path(CONFIG['storage']['recovered_dir']) / recovered_filename
    
    # Mount image
    mount_point = None
    try:
        mount_point = forensic_engine.mount_image(evidence.file_path, evidence.id)
        
        evidence.is_mounted = True
        evidence.mount_point = mount_point
        deleted_file.recovery_status = "in_progress"
        deleted_file.recovery_attempted_at = datetime.utcnow()
        db.commit()
        
        # Recover file using icat
        recovered_path, file_size = forensic_engine.recover_file(
            mount_point,
            partition.start_offset,
            deleted_file.inode,
            str(output_path)
        )
        
        # Calculate hash
        sha256_hash = forensic_engine.calculate_hash(recovered_path)
        
        # Create recovered file record
        recovered_file = RecoveredFile(
            deleted_file_id=deleted_file_id,
            original_filename=deleted_file.filename,
            recovered_filename=recovered_filename,
            file_path=recovered_path,
            size_bytes=file_size,
            sha256_hash=sha256_hash,
            recovery_method="icat",
            recovery_tool="icat (SleuthKit)",
            recovery_command=f"icat -o {partition.start_offset} ewf1 {deleted_file.inode}",
            recovery_success=True,
            file_type=deleted_file.file_type,
            file_extension=deleted_file.file_type
        )
        
        db.add(recovered_file)
        
        # Update deleted file status
        deleted_file.recovery_status = "recovered"
        deleted_file.content_hash = sha256_hash
        
        db.commit()
        db.refresh(recovered_file)
        
        # Audit log
        log_action(
            db=db,
            user=evidence.examiner,
            action="recover_file",
            evidence_id=evidence.id,
            details=f"Recovered file: {deleted_file.filename} (inode {deleted_file.inode})",
            status="success",
            command=f"icat -o {partition.start_offset} {mount_point}/ewf1 {deleted_file.inode}"
        )
        
        # Unmount
        forensic_engine.unmount_image(mount_point)
        evidence.is_mounted = False
        evidence.mount_point = None
        db.commit()
        
        return {
            "success": True,
            "message": "File recovered successfully",
            "recovered_file": recovered_file.to_dict()
        }
    
    except RecoveryError as e:
        deleted_file.recovery_status = "failed"
        deleted_file.recovery_error = str(e)
        db.commit()
        
        log_action(
            db=db,
            user=evidence.examiner,
            action="recover_file",
            evidence_id=evidence.id,
            details=f"Recovery failed: {str(e)}",
            status="failure"
        )
        
        raise HTTPException(status_code=500, detail=f"Recovery error: {str(e)}")
    
    except Exception as e:
        deleted_file.recovery_status = "failed"
        deleted_file.recovery_error = str(e)
        db.commit()
        
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


def background_carve(evidence_id: int, partition_id: int, session_id: str):
    """
    Background worker for carving files with incremental updates.
    """
    from app.database import SessionLocal
    import subprocess
    import time
    
    db = SessionLocal()
    
    # Get session, evidence and partition
    carving_session = db.query(CarvingSession).filter(CarvingSession.session_id == session_id).first()
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    partition = db.query(Partition).filter(Partition.id == partition_id).first()
    
    if not carving_session or not evidence or not partition:
        if carving_session:
            carving_session.status = "failed"
            carving_session.error_message = "Metadata missing at task start"
            db.commit()
        db.close()
        return

    mount_point = None
    process = None
    try:
        # Update session status
        carving_session.status = "in_progress"
        carving_session.started_at = datetime.utcnow()
        carving_session.progress_message = "Mounting evidence image..."
        db.commit()
        
        mount_point = forensic_engine.mount_image(evidence.file_path, evidence_id)
        
        # Prepare Scalpel command
        safe_mount = forensic_engine._sanitize_path(mount_point)
        ewf_file = Path(safe_mount) / "ewf1"
        session_dir = Path(CONFIG['storage']['carved_dir']) / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        scalpel_conf = CONFIG['carving']['scalpel_config']
        
        cmd = [
            forensic_engine.scalpel,
            '-c', scalpel_conf,
            '-o', str(session_dir),
            '-O', # Don't organize by file types (optional, but let's stick to default for now as engine expects it)
            str(ewf_file)
        ]
        # Actually Scalpel -O is 'organize by file types' but it's the default. Let's remove it to stay consistent.
        cmd = [forensic_engine.scalpel, '-c', scalpel_conf, '-o', str(session_dir), str(ewf_file)]

        carving_session.progress_message = "Scalpel scan initiated. Results will appear as found."
        db.commit()

        # Start process
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, # Merge stderr into stdout
            text=True,
            bufsize=1 # Line buffered
        )

        seen_files = set()
        count = 0
        total_bytes = 0

        # Monitor while process is running
        import re
        import os
        
        # Set stdout to non-blocking
        os.set_blocking(process.stdout.fileno(), False)
        
        progress_buffer = ""
        
        while process.poll() is None:
            # Sleep bit to avoid high CPU
            time.sleep(1)
            
            # Read all available output
            try:
                out_chunk = process.stdout.read(4096)
                if out_chunk:
                    progress_buffer += out_chunk
            except Exception:
                pass
                
            # 1. Parse Pass Info (e.g., "Image file pass 1/2")
            pass_matches = re.findall(r'Image file pass (\d+)/(\d+)', progress_buffer)
            current_pass = 1
            total_passes = 1
            if pass_matches:
                current_pass = int(pass_matches[-1][0])
                total_passes = int(pass_matches[-1][1])

            # 2. Parse Percentage (e.g., "10.0%")
            # Fix: (\d+)(?:\.\d+)?% correctly captures the integer part "10" from "10.0%"
            # whereas (\d+)% would incorrectly capture the "0" from "10.0%".
            percent_matches = re.findall(r'(\d+)(?:\.\d+)?%', progress_buffer)
            
            if percent_matches:
                pass_percent = int(percent_matches[-1])
                
                # Calculate normalized overall progress across all passes
                # E.g. Pass 1 of 2 covers 0-50%, Pass 2 of 2 covers 50-100%
                overall_percent = ((current_pass - 1) * 100 + pass_percent) // total_passes
                
                # Update if progress advanced
                if overall_percent > carving_session.progress_percentage:
                    logger.debug(f"Carving session {session_id} progress: {overall_percent}% (Pass {current_pass}/{total_passes}: {pass_percent}%)")
                    carving_session.progress_percentage = min(overall_percent, 99)
            
            # Clear buffer periodically to save memory, but keep enough for context
            if len(progress_buffer) > 10000:
                progress_buffer = progress_buffer[-2000:]
            
            # Scan for new files
            current_files = forensic_engine.parse_carved_files(str(session_dir), session_id)
            
            for file_data in current_files:
                if file_data['file_path'] not in seen_files:
                    # New file found!
                    sha256_hash = forensic_engine.calculate_hash(file_data['file_path'])
                    
                    carved_file = CarvedFile(
                        partition_id=partition_id,
                        carved_filename=file_data['carved_filename'],
                        file_path=file_data['file_path'],
                        size_bytes=file_data['size_bytes'],
                        carving_method='scalpel',
                        signature_type=file_data['signature_type'],
                        file_extension=file_data['signature_type'],
                        sha256_hash=sha256_hash,
                        carving_session_id=session_id,
                        is_complete=True
                    )
                    db.add(carved_file)
                    seen_files.add(file_data['file_path'])
                    count += 1
                    total_bytes += file_data['size_bytes']
            
            # Update session progress
            carving_session.files_carved_count = count
            carving_session.total_bytes_carved = total_bytes
            carving_session.progress_message = f"In Progress: Found {count} files so far... ({carving_session.progress_percentage}%)"
            db.commit()

        # Final scan after completion to catch anything missed
        final_files = forensic_engine.parse_carved_files(str(session_dir), session_id)
        for file_data in final_files:
            if file_data['file_path'] not in seen_files:
                sha256_hash = forensic_engine.calculate_hash(file_data['file_path'])
                carved_file = CarvedFile(
                    partition_id=partition_id,
                    carved_filename=file_data['carved_filename'],
                    file_path=file_data['file_path'],
                    size_bytes=file_data['size_bytes'],
                    carving_method='scalpel',
                    signature_type=file_data['signature_type'],
                    file_extension=file_data['signature_type'],
                    sha256_hash=sha256_hash,
                    carving_session_id=session_id,
                    is_complete=True
                )
                db.add(carved_file)
                seen_files.add(file_data['file_path'])
                count += 1
                total_bytes += file_data['size_bytes']

        # Check exit code
        if process.returncode != 0:
            stdout, stderr = process.communicate()
            logger.warning(f"Scalpel exited with code {process.returncode}. Error: {stderr}")

        # Final update
        carving_session.status = "completed"
        carving_session.completed_at = datetime.utcnow()
        carving_session.progress_percentage = 100
        carving_session.progress_message = f"Completed: Total {count} files carved"
        carving_session.files_carved_count = count
        carving_session.total_bytes_carved = total_bytes
        db.commit()
        
        log_action(
            db=db,
            user=evidence.examiner,
            action="carve_files",
            evidence_id=evidence_id,
            details=f"Incremental carving complete: {count} files",
            status="success"
        )
        
    except Exception as e:
        import traceback
        error_info = f"{str(e)}\n{traceback.format_exc()}"
        carving_session.status = "failed"
        carving_session.error_message = str(e)
        logger.error(f"Incremental carving failed: {error_info}")
        db.commit()
        if process and process.poll() is None:
            process.terminate()
    finally:
        if mount_point:
            forensic_engine.unmount_image(mount_point)
        db.close()


@router.post("/carve", status_code=status.HTTP_202_ACCEPTED)
def carve_files(
    evidence_id: int,
    partition_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Carve files from unallocated space as a background task.
    """
    # Check if evidence and partition exist
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    partition = db.query(Partition).filter(Partition.id == partition_id).first()
    
    if not evidence or not partition:
        raise HTTPException(status_code=404, detail="Evidence or Partition not found")
    
    # Check if a session for this partition is already in progress
    active_session = db.query(CarvingSession).filter(
        CarvingSession.partition_id == partition_id,
        CarvingSession.status.in_(["queued", "in_progress"])
    ).first()
    
    if active_session:
        raise HTTPException(
            status_code=409, 
            detail="Carving session already in progress for this partition"
        )
    
    # Generate session ID
    session_id = f"carve_{evidence_id}_{partition_id}_{uuid.uuid4().hex[:8]}"
    
    # Create session record
    session = CarvingSession(
        evidence_id=evidence_id,
        partition_id=partition_id,
        session_id=session_id,
        status="queued",
        progress_message="Task queued for background execution"
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    
    # Queue the background task
    background_tasks.add_task(background_carve, evidence_id, partition_id, session_id)
    
    return {
        "success": True,
        "message": "Carving task initiated in background",
        "session": session.to_dict()
    }


@router.get("/carve/status/{session_id}")
def get_carving_status(
    session_id: str,
    db: Session = Depends(get_db)
):
    """
    Check the status of a persistent carving session.
    """
    session = db.query(CarvingSession).filter(CarvingSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Carving session not found")
        
    return session.to_dict()


@router.get("/carve/results/{session_id}")
def get_carving_results(
    session_id: str,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Get the files found during a specific carving session.
    """
    session = db.query(CarvingSession).filter(CarvingSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Carving session not found")
        
    carved_files = db.query(CarvedFile).filter(
        CarvedFile.carving_session_id == session_id
    ).offset(skip).limit(limit).all()
    
    return {
        "session": session.to_dict(),
        "files": [cf.to_dict() for cf in carved_files]
    }


@router.post("/batch-recover")
def batch_recover(
    request: BatchRecoverRequest,
    db: Session = Depends(get_db)
):
    """
    Batch recover specific deleted files from a partition.
    
    **Parameters:**
    - evidence_id: The evidence source ID
    - file_ids: List of deleted file IDs to recover
    
    **Returns:** Summary of batch recovery operation
    """
    if not request.file_ids:
        return {
            "success": True,
            "message": "No files to recover",
            "recovered_count": 0
        }
    
    # Recover each file
    recovered_count = 0
    failed_count = 0
    errors = []
    
    for file_id in request.file_ids:
        try:
            # We call the local recover_file function logic
            # To avoid redundant mounting/unmounting, we could refactor 
            # but for now we follow the existing pattern
            recover_file(file_id, db)
            recovered_count += 1
        except HTTPException as e:
            failed_count += 1
            errors.append({"file_id": file_id, "error": str(e.detail)})
        except Exception as e:
            failed_count += 1
            errors.append({"file_id": file_id, "error": str(e)})
            continue
    
    return {
        "success": True,
        "message": f"Batch recovery complete: {recovered_count} succeeded, {failed_count} failed",
        "recovered_count": recovered_count,
        "failed_count": failed_count,
        "total_attempted": len(file_ids),
        "errors": errors
    }
