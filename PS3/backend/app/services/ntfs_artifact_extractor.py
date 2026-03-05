"""
NTFS Artifact Extractor — Phase 1 of Wipe Detection Pipeline.

Extracts the six critical NTFS system metadata files from an E01 disk image
using SleuthKit's icat tool. Each artifact is extracted by its well-known
MFT inode number and saved to disk with a SHA-256 integrity hash.

Artifact    Inode       Purpose
---------   ---------   -----------------------------------------------
$MFT        0           Cluster allocation history (all MFT entries)
$LogFile    2           Transaction/journal history
$AttrDef    4           Attribute type definitions
$Bitmap     6           Current cluster allocation state
$Boot       7           Volume geometry (cluster size, total clusters)
$UsnJrnl:$J 11-128-4   File modification/deletion/overwrite history

FORENSIC: All extractions are read-only icat calls with full audit logging.
"""

import subprocess
import hashlib
import os
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime
from loguru import logger
import yaml

# Load configuration
config_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
if not config_path.exists():
    config_path = Path(__file__).parent.parent.parent / "config" / "config.example.yaml"

with open(config_path, "r") as f:
    CONFIG = yaml.safe_load(f)


# ─────────────────────────────────────────────────────────────────────────────
# Well-known NTFS inode numbers for system metadata files
# ─────────────────────────────────────────────────────────────────────────────
NTFS_SYSTEM_INODES: Dict[str, str] = {
    "$MFT":        "0",         # Master File Table
    "$MFTMirr":    "1",         # MFT mirror (backup first 4 entries)
    "$LogFile":    "2",         # Transaction log
    "$Volume":     "3",         # Volume information
    "$AttrDef":    "4",         # Attribute definitions
    "$Bitmap":     "6",         # Cluster allocation bitmap
    "$Boot":       "7",         # Boot sector / VBR
    "$UsnJrnl:$J": "11-128-4",  # USN Journal data stream (attribute 128, stream 4)
}

# The six Phase-1 required artifacts
PHASE1_ARTIFACTS: List[str] = [
    "$MFT",
    "$LogFile",
    "$AttrDef",
    "$Bitmap",
    "$Boot",
    "$UsnJrnl:$J",
]


class ArtifactExtractionError(Exception):
    """Raised when a single artifact extraction fails."""
    pass


class NTFSArtifactExtractor:
    """
    Extracts NTFS system metadata files from a mounted E01 image.

    Usage:
        extractor = NTFSArtifactExtractor()
        result = extractor.extract_all(
            ewf1_path   = "/path/to/storage/mount/evidence_1/ewf1",
            partition_offset = 2048,       # sectors from mmls
            output_dir  = "/path/to/storage/artifacts/1/"
        )
    """

    def __init__(self) -> None:
        self.icat: str = CONFIG["forensic_tools"]["icat"]
        self.timeout: int = CONFIG["security"]["command_timeout"]
        self.buffer_size: int = CONFIG["hashing"]["buffer_size"]
        self.artifacts_dir = Path(
            CONFIG["storage"].get("artifacts_dir", "./storage/artifacts")
        )
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    # ─────────────────────────────────────────────────────────────────────────
    # Public single-artifact methods
    # ─────────────────────────────────────────────────────────────────────────

    def extract_mft(
        self, ewf1_path: str, partition_offset: int, output_dir: str
    ) -> Dict:
        """Extract $MFT (inode 0) — complete Master File Table."""
        return self._extract(
            artifact_name="$MFT",
            inode=NTFS_SYSTEM_INODES["$MFT"],
            ewf1_path=ewf1_path,
            partition_offset=partition_offset,
            output_dir=output_dir,
        )

    def extract_log_file(
        self, ewf1_path: str, partition_offset: int, output_dir: str
    ) -> Dict:
        """Extract $LogFile (inode 2) — NTFS transaction journal."""
        return self._extract(
            artifact_name="$LogFile",
            inode=NTFS_SYSTEM_INODES["$LogFile"],
            ewf1_path=ewf1_path,
            partition_offset=partition_offset,
            output_dir=output_dir,
        )

    def extract_attr_def(
        self, ewf1_path: str, partition_offset: int, output_dir: str
    ) -> Dict:
        """Extract $AttrDef (inode 4) — attribute type definitions."""
        return self._extract(
            artifact_name="$AttrDef",
            inode=NTFS_SYSTEM_INODES["$AttrDef"],
            ewf1_path=ewf1_path,
            partition_offset=partition_offset,
            output_dir=output_dir,
        )

    def extract_bitmap(
        self, ewf1_path: str, partition_offset: int, output_dir: str
    ) -> Dict:
        """Extract $Bitmap (inode 6) — cluster allocation state."""
        return self._extract(
            artifact_name="$Bitmap",
            inode=NTFS_SYSTEM_INODES["$Bitmap"],
            ewf1_path=ewf1_path,
            partition_offset=partition_offset,
            output_dir=output_dir,
        )

    def extract_boot(
        self, ewf1_path: str, partition_offset: int, output_dir: str
    ) -> Dict:
        """Extract $Boot (inode 7) — volume boot record with geometry info."""
        return self._extract(
            artifact_name="$Boot",
            inode=NTFS_SYSTEM_INODES["$Boot"],
            ewf1_path=ewf1_path,
            partition_offset=partition_offset,
            output_dir=output_dir,
        )

    def extract_usn_journal(
        self, ewf1_path: str, partition_offset: int, output_dir: str
    ) -> Dict:
        """
        Extract $UsnJrnl:$J (inode 11-128-4) — USN change journal.

        NOTE: The inode spec '11-128-4' targets attribute type 128
              ($DATA), instance 4 which is the $J data stream.
              An empty result is valid on volumes with no activity.
        """
        return self._extract(
            artifact_name="$UsnJrnl:$J",
            inode=NTFS_SYSTEM_INODES["$UsnJrnl:$J"],
            ewf1_path=ewf1_path,
            partition_offset=partition_offset,
            output_dir=output_dir,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Bulk extraction
    # ─────────────────────────────────────────────────────────────────────────

    def extract_all(
        self, ewf1_path: str, partition_offset: int, output_dir: str
    ) -> Dict:
        """
        Extract all 6 Phase-1 NTFS artifacts.

        Returns a dict keyed by artifact name:
        {
            "$MFT": {
                "artifact_name": "$MFT",
                "file_path": "/abs/path/MFT.bin",
                "size_bytes": 12345678,
                "sha256_hash": "abc...",
                "extracted_at": datetime,
                "extraction_status": "success" | "failed",
                "error_message": None | "...",
                "inode": "0"
            },
            ...
        }
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        results: Dict[str, Dict] = {}

        for artifact_name in PHASE1_ARTIFACTS:
            logger.info(f"[Phase 1] Extracting {artifact_name} ...")
            try:
                info = self._extract(
                    artifact_name=artifact_name,
                    inode=NTFS_SYSTEM_INODES[artifact_name],
                    ewf1_path=ewf1_path,
                    partition_offset=partition_offset,
                    output_dir=output_dir,
                )
                results[artifact_name] = info
                logger.info(
                    f"[Phase 1] ✓ {artifact_name} extracted "
                    f"({info['size_bytes']:,} bytes) sha256={info['sha256_hash'][:12]}..."
                )
            except ArtifactExtractionError as exc:
                logger.error(f"[Phase 1] ✗ {artifact_name} failed: {exc}")
                results[artifact_name] = {
                    "artifact_name": artifact_name,
                    "inode": NTFS_SYSTEM_INODES[artifact_name],
                    "file_path": None,
                    "size_bytes": 0,
                    "sha256_hash": None,
                    "extracted_at": datetime.utcnow(),
                    "extraction_status": "failed",
                    "error_message": str(exc),
                }

        success_count = sum(
            1 for v in results.values() if v["extraction_status"] == "success"
        )
        logger.info(
            f"[Phase 1] Extraction complete: {success_count}/{len(PHASE1_ARTIFACTS)} succeeded"
        )
        return results

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _safe_filename(self, artifact_name: str) -> str:
        """Convert artifact name to a safe filesystem filename."""
        return artifact_name.lstrip("$").replace(":", "_") + ".bin"

    def _extract(
        self,
        artifact_name: str,
        inode: str,
        ewf1_path: str,
        partition_offset: int,
        output_dir: str,
    ) -> Dict:
        """
        Run icat to extract a single NTFS artifact.

        icat -o <partition_offset_sectors> <ewf1_path> <inode>

        FORENSIC: read-only, no shell, timeout enforced, output hashed.
        """
        ewf1 = Path(ewf1_path)
        if not ewf1.exists():
            raise ArtifactExtractionError(f"ewf1 not found: {ewf1_path}")

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        out_filename = self._safe_filename(artifact_name)
        out_path = out_dir / out_filename

        cmd = [
            self.icat,
            "-o", str(partition_offset),
            str(ewf1),
            inode,
        ]

        logger.debug(f"[icat] {' '.join(cmd)} → {out_path}")

        try:
            with open(out_path, "wb") as f_out:
                proc = subprocess.run(
                    cmd,
                    stdout=f_out,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout,
                    shell=False,  # CRITICAL: no shell injection
                )

            if proc.returncode != 0:
                stderr_msg = proc.stderr.decode(errors="replace").strip()
                # Some system files can legitimately return partial data;
                # only raise if the output file is empty
                if not out_path.exists() or out_path.stat().st_size == 0:
                    out_path.unlink(missing_ok=True)
                    raise ArtifactExtractionError(
                        f"icat returned code {proc.returncode}: {stderr_msg}"
                    )
                logger.warning(
                    f"[icat] {artifact_name} returned rc={proc.returncode} "
                    f"but produced {out_path.stat().st_size} bytes — treating as success"
                )

        except subprocess.TimeoutExpired:
            out_path.unlink(missing_ok=True)
            raise ArtifactExtractionError(
                f"icat timed out after {self.timeout}s for {artifact_name}"
            )
        except OSError as exc:
            raise ArtifactExtractionError(
                f"OS error while extracting {artifact_name}: {exc}"
            )

        # Compute SHA-256
        sha256 = self._sha256(out_path)
        size = out_path.stat().st_size

        return {
            "artifact_name": artifact_name,
            "inode": inode,
            "file_path": str(out_path.resolve()),
            "size_bytes": size,
            "sha256_hash": sha256,
            "extracted_at": datetime.utcnow(),
            "extraction_status": "success",
            "error_message": None,
        }

    def _sha256(self, file_path: Path) -> str:
        """Compute SHA-256 digest of a file (streaming, 64 KB chunks)."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(self.buffer_size):
                hasher.update(chunk)
        return hasher.hexdigest()

    # ─────────────────────────────────────────────────────────────────────────
    # Convenience: build output dir from evidence_id
    # ─────────────────────────────────────────────────────────────────────────

    def artifact_dir_for_evidence(self, evidence_id: int) -> str:
        """Return the canonical output directory for a given evidence_id."""
        d = self.artifacts_dir / str(evidence_id)
        d.mkdir(parents=True, exist_ok=True)
        return str(d)
