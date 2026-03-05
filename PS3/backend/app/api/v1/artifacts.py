"""
NTFS Artifact API Endpoints — Phase 1 of Wipe Detection Pipeline.

Provides endpoints to:
  POST /artifacts/extract               — Extract all 6 NTFS system files
  GET  /artifacts/{evidence_id}         — List artifact metadata
  GET  /artifacts/download/{artifact_id} — Stream artifact file
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pathlib import Path
import yaml

from app.database import get_db
from app.models import Evidence, Partition, NTFSArtifact, log_action
from app.services.ntfs_artifact_extractor import NTFSArtifactExtractor
from app.services.forensic_engine import ForensicEngine, MountError

import logging

logger = logging.getLogger(__name__)

# Load config
config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.yaml"
if not config_path.exists():
    config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.example.yaml"

with open(config_path, "r") as f:
    CONFIG = yaml.safe_load(f)

router = APIRouter()
extractor = NTFSArtifactExtractor()
forensic_engine = ForensicEngine()


# ─────────────────────────────────────────────────────────────────────────────
# POST /artifacts/extract
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/extract",
    status_code=status.HTTP_200_OK,
    summary="Extract NTFS system artifacts",
    description="""
**Phase 1 of Wipe Detection Pipeline**

Mounts the E01 image (read-only), extracts the six required NTFS metadata
files using `icat`, computes SHA-256 hashes for chain-of-custody, stores
metadata in the database, then unmounts.

Extracted artifacts:
| Artifact | Inode | Purpose |
|---|---|---|
| `$MFT` | 0 | Cluster allocation history |
| `$LogFile` | 2 | Transaction history |
| `$AttrDef` | 4 | Attribute definitions |
| `$Bitmap` | 6 | Current allocation state |
| `$Boot` | 7 | Cluster geometry (sector/cluster sizes) |
| `$UsnJrnl:$J` | 11-128-4 | File modification/deletion history |
""",
)
def extract_artifacts(
    evidence_id: int,
    partition_id: int,
    db: Session = Depends(get_db),
):
    """
    Extract all 6 NTFS Phase-1 artifacts for the specified evidence+partition.
    """
    # ── Validate evidence ────────────────────────────────────────────────────
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")

    # ── Validate partition ───────────────────────────────────────────────────
    partition = db.query(Partition).filter(Partition.id == partition_id).first()
    if not partition:
        raise HTTPException(status_code=404, detail=f"Partition {partition_id} not found")

    if partition.evidence_id != evidence_id:
        raise HTTPException(
            status_code=400,
            detail=f"Partition {partition_id} does not belong to evidence {evidence_id}",
        )

    if not partition.is_ntfs:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Partition {partition_id} is not NTFS "
                f"(detected: {partition.filesystem_type}). "
                "NTFS artifacts can only be extracted from NTFS partitions."
            ),
        )

    # ── Mount image ──────────────────────────────────────────────────────────
    mount_point = None
    try:
        mount_point = forensic_engine.mount_image(evidence.file_path, evidence_id)
        evidence.is_mounted = True
        evidence.mount_point = mount_point
        db.commit()

        ewf1_path = str(Path(mount_point) / "ewf1")
        output_dir = extractor.artifact_dir_for_evidence(evidence_id)

        # ── Run extraction ───────────────────────────────────────────────────
        results = extractor.extract_all(
            ewf1_path=ewf1_path,
            partition_offset=partition.start_offset,
            output_dir=output_dir,
        )

        # ── Persist to DB ────────────────────────────────────────────────────
        saved_artifacts = []
        for artifact_name, info in results.items():
            db_artifact = NTFSArtifact(
                evidence_id=evidence_id,
                partition_id=partition_id,
                artifact_name=artifact_name,
                inode=info.get("inode"),
                file_path=info.get("file_path"),
                size_bytes=info.get("size_bytes", 0),
                sha256_hash=info.get("sha256_hash"),
                extracted_at=info.get("extracted_at"),
                extraction_status=info.get("extraction_status", "failed"),
                error_message=info.get("error_message"),
            )
            db.add(db_artifact)
            saved_artifacts.append(db_artifact)

        db.commit()

        # Refresh to get auto-generated IDs
        for a in saved_artifacts:
            db.refresh(a)

        # ── Update evidence status ───────────────────────────────────────────
        evidence.analysis_status = "artifacts_extracted"
        db.commit()

        # ── Audit log ────────────────────────────────────────────────────────
        success_count = sum(
            1 for v in results.values() if v["extraction_status"] == "success"
        )
        log_action(
            db=db,
            user=evidence.examiner,
            action="extract_ntfs_artifacts",
            evidence_id=evidence_id,
            details=(
                f"Phase 1 extraction: {success_count}/{len(results)} artifacts "
                f"succeeded from partition {partition_id} "
                f"(offset {partition.start_offset})"
            ),
            status="success" if success_count == len(results) else "partial",
        )

        return {
            "success": True,
            "evidence_id": evidence_id,
            "partition_id": partition_id,
            "partition_offset": partition.start_offset,
            "output_directory": output_dir,
            "summary": {
                "total": len(results),
                "succeeded": success_count,
                "failed": len(results) - success_count,
            },
            "artifacts": [a.to_dict() for a in saved_artifacts],
        }

    except MountError as exc:
        log_action(
            db=db,
            user=evidence.examiner,
            action="extract_ntfs_artifacts",
            evidence_id=evidence_id,
            details=f"Mount failed: {exc}",
            status="failure",
        )
        raise HTTPException(status_code=500, detail=f"Mount error: {exc}")

    except Exception as exc:
        logger.error(f"Artifact extraction failed for evidence {evidence_id}: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Extraction error: {exc}")

    finally:
        # Always unmount
        if mount_point:
            try:
                forensic_engine.unmount_image(mount_point)
                evidence.is_mounted = False
                evidence.mount_point = None
                db.commit()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# GET /artifacts/{evidence_id}
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/{evidence_id}",
    summary="List extracted NTFS artifacts",
    description="Return all extracted NTFS artifact records for the given evidence image.",
)
def list_artifacts(
    evidence_id: int,
    db: Session = Depends(get_db),
):
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")

    artifacts = (
        db.query(NTFSArtifact)
        .filter(NTFSArtifact.evidence_id == evidence_id)
        .order_by(NTFSArtifact.extracted_at.desc())
        .all()
    )

    return {
        "evidence_id": evidence_id,
        "total": len(artifacts),
        "artifacts": [a.to_dict() for a in artifacts],
    }


# ─────────────────────────────────────────────────────────────────────────────
# GET /artifacts/download/{artifact_id}
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/download/{artifact_id}",
    summary="Download extracted NTFS artifact",
    description="Stream the binary content of an extracted NTFS system file.",
)
def download_artifact(
    artifact_id: int,
    db: Session = Depends(get_db),
):
    artifact = db.query(NTFSArtifact).filter(NTFSArtifact.id == artifact_id).first()
    if not artifact:
        raise HTTPException(status_code=404, detail=f"Artifact {artifact_id} not found")

    if artifact.extraction_status != "success":
        raise HTTPException(
            status_code=400,
            detail=f"Artifact {artifact_id} was not successfully extracted "
                   f"(status: {artifact.extraction_status})",
        )

    if not artifact.file_path or not Path(artifact.file_path).exists():
        raise HTTPException(
            status_code=404,
            detail=f"Artifact file not found on disk: {artifact.file_path}",
        )

    # Safe filename for Content-Disposition
    safe_name = artifact.artifact_name.lstrip("$").replace(":", "_") + ".bin"

    return FileResponse(
        path=artifact.file_path,
        media_type="application/octet-stream",
        filename=safe_name,
        headers={
            "X-Artifact-Name":   artifact.artifact_name,
            "X-Artifact-SHA256": artifact.sha256_hash or "",
            "X-Artifact-Size":   str(artifact.size_bytes),
            "X-Evidence-ID":     str(artifact.evidence_id),
        },
    )
