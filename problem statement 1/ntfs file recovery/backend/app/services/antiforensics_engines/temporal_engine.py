"""
3.1 Temporal Inconsistency Engine
Detects timestomping and timeline manipulation via cross-artifact timestamp matrix.
"""

from __future__ import annotations
from typing import List

from app.models.antiforensics_schemas import (
    TimeVector,
    TemporalFinding,
    TemporalAnalysisResponse,
    DetectionCategory,
)


# ─────────────────────────────────────────────────────
# Detection Rules
# Each rule returns a TemporalFinding or None
# ─────────────────────────────────────────────────────

def _rule_mft_modify_before_usn_first(tv: TimeVector) -> TemporalFinding | None:
    """MFT Modify timestamp precedes the earliest USN entry – impossible without tampering."""
    if tv.mft_modify and tv.usn_first and tv.mft_modify < tv.usn_first:
        return TemporalFinding(
            filename=tv.filename,
            rule_triggered="MFT_MODIFY_BEFORE_USN_FIRST",
            description=(
                f"MFT Modified ({tv.mft_modify.isoformat()}) precedes first USN entry "
                f"({tv.usn_first.isoformat()}). Timestamps may have been retroactively altered."
            ),
            conflicting_artifacts=["MFT", "USN_JOURNAL"],
            severity=0.90,
        )
    return None


def _rule_mft_create_after_logfile_create(tv: TimeVector) -> TemporalFinding | None:
    """MFT Create is newer than $LogFile Create – chronologically impossible."""
    if tv.mft_create and tv.logfile_create and tv.mft_create > tv.logfile_create:
        return TemporalFinding(
            filename=tv.filename,
            rule_triggered="MFT_CREATE_AFTER_LOGFILE_CREATE",
            description=(
                f"MFT Created ({tv.mft_create.isoformat()}) is later than $LogFile Create "
                f"({tv.logfile_create.isoformat()}). File cannot be created after it was logged."
            ),
            conflicting_artifacts=["MFT", "LOG_FILE"],
            severity=0.95,
        )
    return None


def _rule_prefetch_run_before_file_create(tv: TimeVector) -> TemporalFinding | None:
    """Prefetch records execution BEFORE the file was created."""
    if tv.prefetch_last_run and tv.mft_create and tv.prefetch_last_run < tv.mft_create:
        return TemporalFinding(
            filename=tv.filename,
            rule_triggered="PREFETCH_BEFORE_FILE_CREATE",
            description=(
                f"Prefetch last run ({tv.prefetch_last_run.isoformat()}) predates file creation "
                f"({tv.mft_create.isoformat()}). Executable ran before it existed – strong timestomp indicator."
            ),
            conflicting_artifacts=["PREFETCH", "MFT"],
            severity=0.98,
        )
    return None


def _rule_usn_last_before_usn_first(tv: TimeVector) -> TemporalFinding | None:
    """USN last entry is earlier than USN first – sequence inversion."""
    if tv.usn_first and tv.usn_last and tv.usn_last < tv.usn_first:
        return TemporalFinding(
            filename=tv.filename,
            rule_triggered="USN_SEQUENCE_INVERSION",
            description=(
                f"USN Last ({tv.usn_last.isoformat()}) precedes USN First ({tv.usn_first.isoformat()}). "
                f"Journal entries have been reordered or injected."
            ),
            conflicting_artifacts=["USN_JOURNAL"],
            severity=0.85,
        )
    return None


def _rule_mft_access_before_create(tv: TimeVector) -> TemporalFinding | None:
    """File accessed before it was created."""
    if tv.mft_access and tv.mft_create and tv.mft_access < tv.mft_create:
        return TemporalFinding(
            filename=tv.filename,
            rule_triggered="ACCESS_BEFORE_CREATE",
            description=(
                f"MFT Access ({tv.mft_access.isoformat()}) predates MFT Create "
                f"({tv.mft_create.isoformat()}). Access time retroactively set."
            ),
            conflicting_artifacts=["MFT"],
            severity=0.80,
        )
    return None


def _rule_mft_modify_before_create(tv: TimeVector) -> TemporalFinding | None:
    """File modified before it was created."""
    if tv.mft_modify and tv.mft_create and tv.mft_modify < tv.mft_create:
        return TemporalFinding(
            filename=tv.filename,
            rule_triggered="MODIFY_BEFORE_CREATE",
            description=(
                f"MFT Modified ({tv.mft_modify.isoformat()}) predates MFT Create "
                f"({tv.mft_create.isoformat()}). Modification timestamp retroactively set."
            ),
            conflicting_artifacts=["MFT"],
            severity=0.88,
        )
    return None


# ─────────────────────────────────────────────────────
# Engine Entry Point
# ─────────────────────────────────────────────────────

_RULES = [
    _rule_mft_modify_before_usn_first,
    _rule_mft_create_after_logfile_create,
    _rule_prefetch_run_before_file_create,
    _rule_usn_last_before_usn_first,
    _rule_mft_access_before_create,
    _rule_mft_modify_before_create,
]


def analyze_temporal_inconsistencies(time_vectors: List[TimeVector]) -> TemporalAnalysisResponse:
    """
    Run all temporal rules across every TimeVector.
    Returns aggregated findings.
    """
    all_findings: List[TemporalFinding] = []
    flagged_files: set[str] = set()

    for tv in time_vectors:
        for rule in _RULES:
            finding = rule(tv)
            if finding:
                all_findings.append(finding)
                flagged_files.add(tv.filename)

    return TemporalAnalysisResponse(
        total_files=len(time_vectors),
        flagged_files=len(flagged_files),
        findings=all_findings,
        category=DetectionCategory.TEMPORAL,
    )
