"""
Wipe Analysis API Endpoints — Phase 4: Cross-Reference Validation.

POST /wipe/analyze    — Full end-to-end wipe scan (Phases 2→4)
POST /wipe/cluster    — Single-cluster cross-reference (debug / targeted)
GET  /wipe/results/{evidence_id} — Retrieve stored scan summary
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
import yaml

from app.database import get_db
from app.models import Evidence, Partition, NTFSArtifact, log_action
from app.services.wipe_cross_reference import run_full_pipeline, cross_reference_cluster
from app.services.ntfs_parser import NTFSParser
from app.services.wipe_detector import detect_wipe_pattern
from app.services.forensic_engine import ForensicEngine

import logging

logger = logging.getLogger(__name__)

# Load config
config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.yaml"
if not config_path.exists():
    config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.example.yaml"

with open(config_path, "r") as f:
    CONFIG = yaml.safe_load(f)

ARTIFACTS_DIR = CONFIG["storage"].get("artifacts_dir", "./storage/artifacts")
MOUNT_DIR     = CONFIG["storage"].get("mount_dir", "./storage/mount")

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# POST /wipe/analyze
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/analyze",
    summary="Run full wipe detection pipeline (Phases 2–4)",
    description="""
**Full Pipeline: Phase 2 → Phase 3 → Phase 4**

Requires Phase 1 artifacts to have already been extracted via `POST /artifacts/extract`.

1. **Phase 2** — Parses `$MFT`, `$Bitmap`, `$UsnJrnl:$J`, `$LogFile`, `$Boot` into data maps
2. **Phase 3** — Applies 5-rule suspicion scoring engine per unallocated cluster
3. **Phase 4** — Returns cross-referenced evidence verdicts sorted by suspicion score

Returns suspicious clusters with `suspicion_score ≥ min_suspicion` (default 50).
""",
)
def analyze_wipe(
    evidence_id:    int,
    partition_id:   int,
    min_suspicion:  int = 50,
    max_clusters:   Optional[int] = None,
    db: Session = Depends(get_db),
):
    # ── Validate evidence & partition ─────────────────────────────────────
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")

    partition = (
        db.query(Partition)
        .filter(Partition.id == partition_id, Partition.evidence_id == evidence_id)
        .first()
    )
    if not partition:
        raise HTTPException(status_code=404, detail=f"Partition {partition_id} not found")

    # ── Check Phase 1 artifacts exist ─────────────────────────────────────
    artifacts = (
        db.query(NTFSArtifact)
        .filter(
            NTFSArtifact.evidence_id == evidence_id,
            NTFSArtifact.extraction_status == "success",
        )
        .all()
    )
    artifact_names = {a.artifact_name for a in artifacts}
    required = {"$MFT", "$Bitmap", "$Boot"}   # $UsnJrnl:$J and $LogFile are optional
    missing  = required - artifact_names
    if missing:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Required Phase-1 artifacts not yet extracted: {missing}. "
                "Run POST /api/v1/artifacts/extract first."
            ),
        )

    # ── Resolve ewf1 path ─────────────────────────────────────────────────
    mount_point = Path(MOUNT_DIR) / f"evidence_{evidence_id}"
    ewf1_path   = str(mount_point / "ewf1")

    if not Path(ewf1_path).exists():
        # Auto-mount if not currently mounted
        try:
            logger.info(f"Auto-mounting evidence {evidence_id} for wipe analysis...")
            engine = ForensicEngine()
            engine.mount_image(evidence.file_path, evidence.id)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to auto-mount evidence image: {str(e)}"
            )
            
        if not Path(ewf1_path).exists():
            raise HTTPException(
                status_code=400,
                detail="ewf1 not successfully mounted after attempt."
            )

    # ── Run pipeline ──────────────────────────────────────────────────────
    try:
        result = run_full_pipeline(
            evidence_id=evidence_id,
            partition_id=partition_id,
            ewf1_path=ewf1_path,
            partition_offset_sectors=partition.start_offset,
            artifacts_base_dir=ARTIFACTS_DIR,
            acquisition_time=datetime.now(tz=timezone.utc),
            min_suspicion=min_suspicion,
            max_clusters=max_clusters,
        )

        # ── Audit log ────────────────────────────────────────────────────
        summary = result["summary"]
        log_action(
            db=db,
            user=evidence.examiner,
            action="wipe_analysis",
            evidence_id=evidence_id,
            details=(
                f"Phase2-4 wipe scan: "
                f"{summary['suspicious_total']} suspicious clusters "
                f"(HIGH={summary['high_confidence']}, "
                f"MED={summary['medium_confidence']}, "
                f"LOW={summary['low_confidence']})"
            ),
            status="success",
        )

        return result

    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.error(
            f"Wipe analysis failed for evidence {evidence_id}: {exc}",
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail=f"Wipe analysis error: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# POST /wipe/cluster  — single cluster targeted analysis
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/cluster",
    summary="Cross-reference a single cluster (targeted debug)",
    description="""
Reads a single cluster from the mounted image and runs Phase 2→4 analysis
on it. Useful for investigating a specific LCN without a full scan.
""",
)
def analyze_single_cluster(
    evidence_id:     int,
    partition_id:    int,
    cluster_number:  int,
    db: Session = Depends(get_db),
):
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    partition = (
        db.query(Partition)
        .filter(Partition.id == partition_id, Partition.evidence_id == evidence_id)
        .first()
    )
    if not partition:
        raise HTTPException(status_code=404, detail="Partition not found")

    mount_point = Path(MOUNT_DIR) / f"evidence_{evidence_id}"
    ewf1_path   = mount_point / "ewf1"
    
    if not ewf1_path.exists():
        # Auto-mount
        try:
            engine = ForensicEngine()
            engine.mount_image(evidence.file_path, evidence.id)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to auto-mount evidence image: {str(e)}")
            
        if not ewf1_path.exists():
            raise HTTPException(status_code=400, detail="ewf1 not available after mount attempt")

    artifacts_base = Path(ARTIFACTS_DIR) / str(evidence_id)
    parser = NTFSParser()

    try:
        # Parse geometry first
        boot_path = artifacts_base / "Boot.bin"
        geometry  = parser.parse_boot(str(boot_path)) if boot_path.exists() else {}
        bps = geometry.get("bytes_per_sector", 512)
        bpc = geometry.get("bytes_per_cluster", 4096)

        # Read maps
        bitmap_path  = artifacts_base / "Bitmap.bin"
        mft_path     = artifacts_base / "MFT.bin"
        usn_path     = artifacts_base / "UsnJrnl_J.bin"
        logfile_path = artifacts_base / "LogFile.bin"

        allocation_map  = {}
        highest         = -1
        hist_map        = {}
        usn_map         = {}
        logfile_ev      = {}

        if bitmap_path.exists():
            allocation_map, highest = parser.parse_bitmap(str(bitmap_path))
        if mft_path.exists():
            hist_map = parser.parse_mft(str(mft_path), bpc)
        if usn_path.exists():
            usn_map = parser.parse_usn_journal(str(usn_path))
        if logfile_path.exists():
            logfile_ev = parser.parse_logfile(str(logfile_path))

        # Read raw cluster data
        cluster_offset = (partition.start_offset * bps) + (cluster_number * bpc)
        with open(ewf1_path, "rb") as f:
            f.seek(cluster_offset)
            cluster_data = f.read(bpc)

        verdict = cross_reference_cluster(
            cluster_number=cluster_number,
            cluster_data=cluster_data,
            allocation_map=allocation_map,
            cluster_history_map=hist_map,
            usn_map=usn_map,
            logfile_events=logfile_ev,
        )

        return {
            "success":  True,
            "geometry": geometry,
            "verdict":  verdict,
        }

    except Exception as exc:
        logger.error(f"Single-cluster analysis failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# POST /wipe/pattern  — quick pattern test on arbitrary hex / bytes
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/pattern",
    summary="Test wipe pattern detection on raw bytes (hex string)",
    description="""
Debug endpoint: submit a hex-encoded byte string and receive the
Phase-3 pattern classification (verdict, entropy, dominant byte, etc.).

Example body:  `{ "hex_data": "00000000000000000000" }`
""",
)
def detect_pattern(hex_data: str):
    try:
        raw = bytes.fromhex(hex_data.replace(" ", ""))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex string")

    result = detect_wipe_pattern(raw)
    return {"success": True, "analysis": result}
