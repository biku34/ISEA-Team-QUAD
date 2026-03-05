"""
3.6 Shadow Copy Tampering Detection Engine
Detects VSS deletion events, vssadmin Prefetch traces, and the full anti-forensic chain.
"""

from __future__ import annotations
from datetime import timedelta
from typing import List, Optional

from app.models.antiforensics_schemas import (
    ShadowCopyEvent,
    PrefetchEntry,
    BurstFinding,
    ShadowCopyFinding,
    ShadowCopyResponse,
    DetectionCategory,
)

# Windows Event IDs associated with VSS / shadow copy operations
VSS_DELETION_EVENT_IDS = {
    8197,   # VSS – shadow copy deletion
    8193,   # VSS – service error (often accompanies forceful removal)
    524,    # Security – Audit log cleared
    1102,   # Security – Audit log cleared (newer Windows)
    104,    # System – Event log cleared
}

VSSADMIN_EXECUTABLES = {"vssadmin.exe", "vssadmin", "wmic.exe"}


# ─────────────────────────────────────────────────────
# Sub-detectors
# ─────────────────────────────────────────────────────

def _count_vss_deletions(events: List[ShadowCopyEvent]) -> int:
    return sum(1 for e in events if e.event_id in VSS_DELETION_EVENT_IDS)


def _check_vssadmin_prefetch(prefetch: Optional[List[PrefetchEntry]]) -> bool:
    if not prefetch:
        return False
    return any(
        p.executable.lower() in VSSADMIN_EXECUTABLES
        for p in prefetch
    )


def _missing_restore_points(restore_points: Optional[List]) -> int:
    """
    Heuristic: at least one restore point expected per 24h of activity.
    Returns estimated count of missing points.
    """
    if restore_points is None:
        return 0
    if not restore_points:
        return 1  # No restore points at all = suspicious
    sorted_rp = sorted(restore_points)
    gaps = 0
    for i in range(1, len(sorted_rp)):
        delta = sorted_rp[i] - sorted_rp[i - 1]
        if delta > timedelta(hours=48):
            gaps += int(delta.total_seconds() / 86400)
    return gaps


# ─────────────────────────────────────────────────────
# Anti-Forensic Chain Detection
# Burst → Shadow Delete → Log Clear → Reboot
# ─────────────────────────────────────────────────────

def _detect_anti_forensic_chain(
    events: List[ShadowCopyEvent],
    burst_findings: Optional[List[BurstFinding]],
) -> List[ShadowCopyFinding]:
    """
    Looks for the pattern:
      1. High deletion burst
      2. VSS / shadow deletion
      3. Event log clearing
      4. System reboot (optional)
    within a rolling 30-minute window.
    """
    findings: List[ShadowCopyFinding] = []

    if not events:
        return findings

    LOG_CLEAR_IDS = {524, 1102, 104}
    VSS_DELETE_IDS = {8197, 8193}
    REBOOT_IDS = {6006, 6008, 41}  # System shutdown / unexpected reboot

    sorted_events = sorted(events, key=lambda e: e.timestamp)

    for anchor_idx, anchor in enumerate(sorted_events):
        window_end = anchor.timestamp + timedelta(minutes=30)
        window_events = [e for e in sorted_events if anchor.timestamp <= e.timestamp <= window_end]

        window_ids = {e.event_id for e in window_events}
        has_burst = bool(burst_findings and any(
            anchor.timestamp <= b.window_start <= window_end
            for b in burst_findings
        ))
        has_vss_delete = bool(window_ids & VSS_DELETE_IDS)
        has_log_clear = bool(window_ids & LOG_CLEAR_IDS)
        has_reboot = bool(window_ids & REBOOT_IDS)

        chain_score = sum([has_burst, has_vss_delete, has_log_clear, has_reboot])

        if chain_score >= 2:
            evidence = []
            if has_burst:
                evidence.append("Deletion burst detected near this timeframe")
            if has_vss_delete:
                evidence.append(f"VSS deletion event(s): {window_ids & VSS_DELETE_IDS}")
            if has_log_clear:
                evidence.append(f"Event log cleared: {window_ids & LOG_CLEAR_IDS}")
            if has_reboot:
                evidence.append("System reboot detected after clearing")

            findings.append(
                ShadowCopyFinding(
                    timestamp=anchor.timestamp,
                    indicator="ANTI_FORENSIC_CHAIN",
                    evidence=evidence,
                    chain_detected=chain_score >= 3,
                    severity=min(0.4 + chain_score * 0.15, 1.0),
                )
            )

    # Deduplicate – keep highest severity per 30-min window
    seen_windows: set = set()
    deduped: List[ShadowCopyFinding] = []
    for f in sorted(findings, key=lambda x: x.severity, reverse=True):
        bucket = f.timestamp.replace(second=0, microsecond=0)
        bucket = bucket - timedelta(minutes=bucket.minute % 30)
        if bucket not in seen_windows:
            seen_windows.add(bucket)
            deduped.append(f)

    return deduped


# ─────────────────────────────────────────────────────
# Engine Entry Point
# ─────────────────────────────────────────────────────

def analyze_shadow_copy_tampering(
    event_log_entries: List[ShadowCopyEvent],
    prefetch_entries: Optional[List[PrefetchEntry]],
    restore_points: Optional[List],
    burst_findings: Optional[List[BurstFinding]],
) -> ShadowCopyResponse:
    vss_count = _count_vss_deletions(event_log_entries)
    vssadmin_found = _check_vssadmin_prefetch(prefetch_entries)
    missing_rp = _missing_restore_points(restore_points)
    chain_findings = _detect_anti_forensic_chain(event_log_entries, burst_findings)
    chain_detected = any(f.chain_detected for f in chain_findings)

    return ShadowCopyResponse(
        vss_deletion_events=vss_count,
        vssadmin_prefetch_found=vssadmin_found,
        missing_restore_points=missing_rp,
        anti_forensic_chain_detected=chain_detected,
        findings=chain_findings,
        category=DetectionCategory.BEHAVIORAL,
    )
