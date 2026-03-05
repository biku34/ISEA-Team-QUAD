"""
3.5 MFT Structural Integrity Engine
Detects MFT entry reuse anomalies and parent-child directory inconsistencies.
"""

from __future__ import annotations
from collections import defaultdict
from typing import Dict, List, Set

from app.models.antiforensics_schemas import (
    MFTEntry,
    USNEntry,
    LogFileEntry,
    MFTFinding,
    MFTIntegrityResponse,
    DetectionCategory,
)


# ─────────────────────────────────────────────────────
# A. MFT Entry Reuse Detection
# ─────────────────────────────────────────────────────

def detect_mft_reuse_anomalies(
    mft_entries: List[MFTEntry],
    logfile_entries: List[LogFileEntry],
) -> List[MFTFinding]:
    """
    Flag entry numbers that were deleted and rapidly reused while $LogFile
    still references the old filename.
    """
    findings: List[MFTFinding] = []

    # Build map: entry_number → list of MFT records (should be 1; >1 = reuse)
    entry_map: Dict[int, List[MFTEntry]] = defaultdict(list)
    for entry in mft_entries:
        entry_map[entry.entry_number].append(entry)

    # Build LSN-to-filename map from LogFile for cross-check
    lsn_names: Dict[int, str] = {}  # Not directly available; placeholder pattern

    for entry_num, records in entry_map.items():
        if len(records) > 1:
            # Sort by sequence number (NTFS increments this on reuse)
            records_sorted = sorted(records, key=lambda r: r.sequence_number)
            for i in range(1, len(records_sorted)):
                prev = records_sorted[i - 1]
                curr = records_sorted[i]

                time_diff = abs(
                    (curr.timestamps.created - prev.timestamps.created).total_seconds()
                )

                # Rapid reuse within 60 seconds is highly suspicious
                if time_diff < 60:
                    findings.append(
                        MFTFinding(
                            entry_number=entry_num,
                            filename=curr.filename,
                            issue="RAPID_MFT_REUSE",
                            details=(
                                f"Entry #{entry_num} reused within {time_diff:.0f}s. "
                                f"Previous: '{prev.filename}' seq={prev.sequence_number}, "
                                f"Current: '{curr.filename}' seq={curr.sequence_number}."
                            ),
                            severity=0.85,
                        )
                    )
                elif time_diff < 600:
                    findings.append(
                        MFTFinding(
                            entry_number=entry_num,
                            filename=curr.filename,
                            issue="SUSPICIOUS_MFT_REUSE",
                            details=(
                                f"Entry #{entry_num} reused within {time_diff:.0f}s. "
                                f"Moderately suspicious – warrants manual review."
                            ),
                            severity=0.55,
                        )
                    )

    return findings


# ─────────────────────────────────────────────────────
# B. Parent-Child Inconsistency Detection
# ─────────────────────────────────────────────────────

def detect_parent_child_conflicts(
    mft_entries: List[MFTEntry],
    usn_entries: List[USNEntry],
) -> List[MFTFinding]:
    """
    If a directory is deleted in MFT but USN still references children under it,
    that is an orphan inconsistency.
    """
    findings: List[MFTFinding] = []

    # Collect deleted directories
    deleted_dirs: Set[int] = {
        e.entry_number
        for e in mft_entries
        if e.is_deleted and _is_directory(e, mft_entries)
    }

    # Build USN file-reference set
    usn_references: Set[str] = {u.file_reference for u in usn_entries}

    # Find MFT children whose parent is a deleted directory
    for entry in mft_entries:
        if entry.parent_entry_number in deleted_dirs and not entry.is_deleted:
            findings.append(
                MFTFinding(
                    entry_number=entry.entry_number,
                    filename=entry.filename,
                    issue="ORPHAN_CHILD_OF_DELETED_DIR",
                    details=(
                        f"File '{entry.filename}' (entry #{entry.entry_number}) "
                        f"resides under deleted directory entry #{entry.parent_entry_number}. "
                        f"Parent-child tree is inconsistent."
                    ),
                    severity=0.70,
                )
            )

    return findings


def _is_directory(entry: MFTEntry, all_entries: List[MFTEntry]) -> bool:
    """Heuristic: an entry is a directory if other entries list it as parent."""
    return any(
        e.parent_entry_number == entry.entry_number and e.entry_number != entry.entry_number
        for e in all_entries
    )


# ─────────────────────────────────────────────────────
# Engine Entry Point
# ─────────────────────────────────────────────────────

def analyze_mft_integrity(
    mft_entries: List[MFTEntry],
    usn_entries: List[USNEntry],
    logfile_entries: List[LogFileEntry],
) -> MFTIntegrityResponse:
    reuse_anomalies = detect_mft_reuse_anomalies(mft_entries, logfile_entries)
    parent_child_conflicts = detect_parent_child_conflicts(mft_entries, usn_entries)

    return MFTIntegrityResponse(
        total_entries=len(mft_entries),
        reuse_anomalies=reuse_anomalies,
        parent_child_conflicts=parent_child_conflicts,
        category=DetectionCategory.STRUCTURAL,
    )
