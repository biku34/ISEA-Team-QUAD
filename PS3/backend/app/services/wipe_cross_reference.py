"""
Wipe Cross-Reference — Phase 4: Master validation function.

Combines all Phase-2 data maps with Phase-3 wipe analysis to produce
a structured evidence verdict per cluster, and provides a batch
scan function that processes an entire partition's unallocated space.

Entry point:
    cross_reference_cluster(cluster_number, ...)  → single cluster verdict
    batch_scan(ewf1_path, ...)                    → list of per-cluster verdicts
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from loguru import logger

from app.services.wipe_detector import analyze_cluster, PATTERN_NONE
from app.services.ntfs_parser import NTFSParser


# ═══════════════════════════════════════════════════════════════════════════
# Single-cluster cross-reference
# ═══════════════════════════════════════════════════════════════════════════

def cross_reference_cluster(
    cluster_number:      int,
    cluster_data:        bytes,
    allocation_map:      Dict[int, bool],
    cluster_history_map: Dict[int, Dict],
    usn_map:             Dict[int, List[Dict]],
    logfile_events:      Dict[int, List[str]],
    acquisition_time:    Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Master validation function — Phase 4.

    Runs the Phase-3 suspicion engine on a single cluster and returns
    a fully structured evidence verdict matching the spec:

    {
      "cluster":           int,
      "current_allocated": bool,
      "previous_owner":    str | None,
      "file_reference":    int | None,
      "usn_events":        [str],          # wipe-relevant reason strings
      "logfile_events":    [str],
      "wipe_pattern":      str,
      "entropy":           float,
      "dominant_byte":     int,
      "dominant_frac":     float,
      "suspicion_score":   int,            # 0–100
      "confidence_level":  "HIGH"|"MEDIUM"|"LOW",
      "rules_triggered":   [str],
      "timestamps":        {created, modified, ...} | None,
    }
    """
    return analyze_cluster(
        cluster_number=cluster_number,
        cluster_data=cluster_data,
        allocation_map=allocation_map,
        cluster_history_map=cluster_history_map,
        usn_map=usn_map,
        logfile_events=logfile_events,
        acquisition_time=acquisition_time,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Batch scanner — reads raw cluster data from the ewf1 device
# ═══════════════════════════════════════════════════════════════════════════

def batch_scan(
    ewf1_path:           str,
    partition_offset_sectors: int,
    bytes_per_sector:    int,
    bytes_per_cluster:   int,
    allocation_map:      Dict[int, bool],
    cluster_history_map: Dict[int, Dict],
    usn_map:             Dict[int, List[Dict]],
    logfile_events:      Dict[int, List[str]],
    highest_cluster:     int,
    acquisition_time:    Optional[datetime] = None,
    min_suspicion:       int = 50,
    skip_allocated:      bool = True,
    max_clusters:        Optional[int] = None,
    progress_callback=None,
) -> List[Dict]:
    """
    Scan all (or a subset of) unallocated clusters from the raw ewf1 device.

    Parameters
    ----------
    ewf1_path                : Path to mounted ewf1 file
    partition_offset_sectors : Partition start in sectors (from mmls)
    bytes_per_sector         : From $Boot geometry
    bytes_per_cluster        : From $Boot geometry
    allocation_map           : Phase-2 bitmap map
    cluster_history_map      : Phase-2 MFT map
    usn_map                  : Phase-2 USN map
    logfile_events           : Phase-2 LogFile map
    highest_cluster          : Last allocated cluster (scan boundary)
    acquisition_time         : When the image was acquired
    min_suspicion            : Only include results above this score (0 = all)
    skip_allocated           : Skip currently allocated clusters (default True)
    max_clusters             : Safety cap on total clusters to scan
    progress_callback        : Optional callable(scanned, total) for progress

    Returns
    -------
    List of cross_reference_cluster() dicts with suspicion_score >= min_suspicion,
    sorted by suspicion_score descending.
    """
    ewf1 = Path(ewf1_path)
    if not ewf1.exists():
        raise FileNotFoundError(f"ewf1 not found: {ewf1_path}")

    partition_start_bytes = partition_offset_sectors * bytes_per_sector
    total_to_scan = min(highest_cluster + 1, max_clusters or highest_cluster + 1)

    logger.info(
        f"[Phase4] Batch scan: {total_to_scan:,} clusters, "
        f"offset={partition_offset_sectors} sectors, "
        f"{bytes_per_cluster}B/cluster, "
        f"min_score={min_suspicion}"
    )

    results: List[Dict] = []
    scanned = 0
    skipped_alloc = 0

    with open(ewf1_path, "rb") as f:
        for lcn in range(total_to_scan):
            # Skip allocated clusters if requested
            if skip_allocated and allocation_map.get(lcn, True):
                skipped_alloc += 1
                scanned += 1
                if progress_callback and scanned % 10000 == 0:
                    progress_callback(scanned, total_to_scan)
                continue

            # Read raw cluster from ewf1
            cluster_offset = partition_start_bytes + (lcn * bytes_per_cluster)
            try:
                f.seek(cluster_offset)
                cluster_data = f.read(bytes_per_cluster)
            except OSError as exc:
                logger.warning(f"[Phase4] Read error at LCN {lcn}: {exc}")
                scanned += 1
                continue

            if not cluster_data:
                scanned += 1
                continue

            verdict = cross_reference_cluster(
                cluster_number=lcn,
                cluster_data=cluster_data,
                allocation_map=allocation_map,
                cluster_history_map=cluster_history_map,
                usn_map=usn_map,
                logfile_events=logfile_events,
                acquisition_time=acquisition_time,
            )

            if verdict["suspicion_score"] >= min_suspicion:
                results.append(verdict)

            scanned += 1
            if progress_callback and scanned % 10000 == 0:
                progress_callback(scanned, total_to_scan)

    results.sort(key=lambda r: r["suspicion_score"], reverse=True)

    logger.info(
        f"[Phase4] Scan complete: {scanned:,} clusters scanned, "
        f"{skipped_alloc:,} allocated skipped, "
        f"{len(results):,} suspicious clusters found (score≥{min_suspicion})"
    )
    return results


# ═══════════════════════════════════════════════════════════════════════════
# Full pipeline runner (Phases 1→2→3→4)
# ═══════════════════════════════════════════════════════════════════════════

def run_full_pipeline(
    evidence_id:          int,
    partition_id:         int,
    ewf1_path:            str,
    partition_offset_sectors: int,
    artifacts_base_dir:   str,
    acquisition_time:     Optional[datetime] = None,
    min_suspicion:        int = 50,
    max_clusters:         Optional[int] = None,
) -> Dict[str, Any]:
    """
    Convenience runner: Phase 2 parse → Phase 4 batch scan.

    Assumes Phase-1 artifacts already extracted to:
      {artifacts_base_dir}/{evidence_id}/MFT.bin
      {artifacts_base_dir}/{evidence_id}/Bitmap.bin
      ...

    Returns:
        {
          "geometry":       {...},
          "summary":        {...},
          "suspicious_clusters": [...],   # sorted desc by suspicion_score
        }
    """
    base = Path(artifacts_base_dir) / str(evidence_id)

    def art(name: str) -> str:
        return str(base / name)

    parser = NTFSParser()

    # ── Phase 2: parse all artifacts ─────────────────────────────────────
    data = parser.parse_all(
        mft_path     = art("MFT.bin"),
        bitmap_path  = art("Bitmap.bin"),
        usn_path     = art("UsnJrnl_J.bin"),
        logfile_path = art("LogFile.bin"),
        boot_path    = art("Boot.bin"),
    )

    geometry        = data["geometry"]
    allocation_map  = data["allocation_map"]
    highest         = data["highest_allocated"]
    hist_map        = data["cluster_history_map"]
    usn_map         = data["usn_map"]
    logfile_ev      = data["logfile_events"]

    bps  = geometry.get("bytes_per_sector", 512)
    bpc  = geometry.get("bytes_per_cluster", 4096)

    # ── Phase 4: batch scan ───────────────────────────────────────────────
    suspicious = batch_scan(
        ewf1_path=ewf1_path,
        partition_offset_sectors=partition_offset_sectors,
        bytes_per_sector=bps,
        bytes_per_cluster=bpc,
        allocation_map=allocation_map,
        cluster_history_map=hist_map,
        usn_map=usn_map,
        logfile_events=logfile_ev,
        highest_cluster=highest,
        acquisition_time=acquisition_time,
        min_suspicion=min_suspicion,
        max_clusters=max_clusters,
    )

    # ── Build summary ─────────────────────────────────────────────────────
    high   = sum(1 for r in suspicious if r["confidence_level"] == "HIGH")
    medium = sum(1 for r in suspicious if r["confidence_level"] == "MEDIUM")
    low    = sum(1 for r in suspicious if r["confidence_level"] == "LOW")

    return {
        "evidence_id":    evidence_id,
        "partition_id":   partition_id,
        "geometry":       geometry,
        "data_maps": {
            "total_clusters_in_bitmap": len(allocation_map),
            "allocated_clusters":       sum(allocation_map.values()),
            "mft_entries_mapped":       len(hist_map),
            "usn_file_references":      len(usn_map),
            "logfile_events":           len(logfile_ev),
        },
        "summary": {
            "suspicious_total": len(suspicious),
            "high_confidence":  high,
            "medium_confidence": medium,
            "low_confidence":   low,
            "min_suspicion_threshold": min_suspicion,
        },
        "suspicious_clusters": suspicious,
    }
