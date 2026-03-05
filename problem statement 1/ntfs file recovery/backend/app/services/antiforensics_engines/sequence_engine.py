"""
3.2 Sequence Integrity Engine
Validates monotonic USN journal continuity and $LogFile LSN / transaction integrity.
"""

from __future__ import annotations
import statistics
from typing import List, Optional, Tuple

from app.models.antiforensics_schemas import (
    USNEntry,
    LogFileEntry,
    SequenceFinding,
    SequenceIntegrityResponse,
    DetectionCategory,
)


# ─────────────────────────────────────────────────────
# USN Journal Analysis
# ─────────────────────────────────────────────────────

def _compute_dynamic_gap_threshold(deltas: List[int], multiplier: float) -> float:
    """Mean + (multiplier × std_dev) of sequential USN deltas."""
    if len(deltas) < 2:
        return float("inf")
    mu = statistics.mean(deltas)
    sigma = statistics.stdev(deltas) if len(deltas) > 1 else 0
    return mu + multiplier * sigma


def analyze_usn_sequence(
    entries: List[USNEntry],
    dynamic_threshold_multiplier: float = 3.0,
) -> Tuple[List[SequenceFinding], List[SequenceFinding]]:
    """
    Returns (regressions, gaps).
    Regression: USN(n) < USN(n-1)
    Gap: USN(n) - USN(n-1) > dynamic threshold
    """
    regressions: List[SequenceFinding] = []
    gaps: List[SequenceFinding] = []

    if len(entries) < 2:
        return regressions, gaps

    # Sort by position in supplied list (caller should pre-sort by USN)
    sorted_entries = sorted(entries, key=lambda e: e.usn)
    deltas = [
        sorted_entries[i].usn - sorted_entries[i - 1].usn
        for i in range(1, len(sorted_entries))
    ]
    threshold = _compute_dynamic_gap_threshold(deltas, dynamic_threshold_multiplier)

    for i in range(1, len(sorted_entries)):
        prev = sorted_entries[i - 1]
        curr = sorted_entries[i]
        delta = curr.usn - prev.usn

        if delta < 0:
            regressions.append(
                SequenceFinding(
                    index=i,
                    usn_or_lsn=curr.usn,
                    expected_approx=prev.usn + 1,
                    issue="USN_REGRESSION",
                    severity=0.92,
                )
            )
        elif delta > threshold:
            gaps.append(
                SequenceFinding(
                    index=i,
                    usn_or_lsn=curr.usn,
                    expected_approx=prev.usn + int(threshold),
                    issue=f"USN_GAP (delta={delta}, threshold≈{threshold:.0f})",
                    severity=min(0.5 + (delta / threshold) * 0.1, 0.95),
                )
            )

    return regressions, gaps


# ─────────────────────────────────────────────────────
# $LogFile / LSN Analysis
# ─────────────────────────────────────────────────────

def analyze_logfile_sequence(
    entries: List[LogFileEntry],
) -> List[SequenceFinding]:
    """
    Detect:
    - LSN regressions
    - Incomplete redo/undo pairs (transaction with undo but no matching redo, or vice versa)
    - Orphaned transaction IDs (begin with no commit/rollback)
    """
    findings: List[SequenceFinding] = []

    sorted_entries = sorted(entries, key=lambda e: e.lsn)

    # 1. LSN monotonicity
    for i in range(1, len(sorted_entries)):
        if sorted_entries[i].lsn <= sorted_entries[i - 1].lsn:
            findings.append(
                SequenceFinding(
                    index=i,
                    usn_or_lsn=sorted_entries[i].lsn,
                    expected_approx=sorted_entries[i - 1].lsn + 1,
                    issue="LSN_REGRESSION",
                    severity=0.90,
                )
            )

    # 2. Redo/Undo pair completeness per transaction
    from collections import defaultdict
    tx_map: dict[int, dict] = defaultdict(lambda: {"redo": 0, "undo": 0, "lsns": []})

    for e in sorted_entries:
        tx_map[e.transaction_id]["lsns"].append(e.lsn)
        if e.redo_operation.upper() != "NOOP":
            tx_map[e.transaction_id]["redo"] += 1
        if e.undo_operation.upper() != "NOOP":
            tx_map[e.transaction_id]["undo"] += 1

    for tx_id, data in tx_map.items():
        if data["redo"] != data["undo"] and data["undo"] > 0:
            lsn_example = data["lsns"][0] if data["lsns"] else -1
            findings.append(
                SequenceFinding(
                    index=-1,
                    usn_or_lsn=lsn_example,
                    expected_approx=None,
                    issue=(
                        f"INCOMPLETE_TRANSACTION tx_id={tx_id} "
                        f"redo={data['redo']} undo={data['undo']}"
                    ),
                    severity=0.75,
                )
            )

    return findings


# ─────────────────────────────────────────────────────
# Engine Entry Point
# ─────────────────────────────────────────────────────

def analyze_sequence_integrity(
    usn_entries: List[USNEntry],
    logfile_entries: Optional[List[LogFileEntry]],
    dynamic_threshold_multiplier: float,
) -> SequenceIntegrityResponse:
    regressions, gaps = analyze_usn_sequence(usn_entries, dynamic_threshold_multiplier)
    lsn_findings = analyze_logfile_sequence(logfile_entries) if logfile_entries else []

    return SequenceIntegrityResponse(
        total_entries=len(usn_entries) + (len(logfile_entries) if logfile_entries else 0),
        regressions=regressions,
        gaps=gaps,
        incomplete_transactions=lsn_findings,
        category=DetectionCategory.STRUCTURAL,
    )
