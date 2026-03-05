"""
3.3 Burst & Behavioral Anomaly Detection Engine
Detects deletion bursts and log-silence gaps using statistical baseline modeling.
"""

from __future__ import annotations
import statistics
from collections import defaultdict
from datetime import timedelta
from typing import List, Optional

from app.models.antiforensics_schemas import (
    DeletionEvent,
    TimelineEvent,
    BurstFinding,
    BehavioralAnalysisResponse,
    DetectionCategory,
)


# ─────────────────────────────────────────────────────
# A. Deletion Burst Detector
# ─────────────────────────────────────────────────────

def _bucket_deletions(
    events: List[DeletionEvent],
    window_minutes: int,
) -> dict:
    """
    Group deletion events into fixed-width time buckets.
    Returns { bucket_start: count }
    """
    if not events:
        return {}

    buckets: dict = defaultdict(int)
    for ev in events:
        # Floor timestamp to nearest window
        ts = ev.timestamp
        floored = ts - timedelta(
            minutes=ts.minute % window_minutes,
            seconds=ts.second,
            microseconds=ts.microsecond,
        )
        buckets[floored] += 1
    return dict(sorted(buckets.items()))


def detect_deletion_bursts(
    events: List[DeletionEvent],
    sigma_threshold: float,
    window_minutes: int,
) -> List[BurstFinding]:
    """
    Raise a BurstFinding for any bucket exceeding μ + sigma_threshold × σ.
    """
    buckets = _bucket_deletions(events, window_minutes)
    if len(buckets) < 3:
        return []  # Need baseline data

    rates = list(buckets.values())
    mu = statistics.mean(rates)
    sigma = statistics.stdev(rates) if len(rates) > 1 else 0.0
    cutoff = mu + sigma_threshold * sigma

    findings: List[BurstFinding] = []
    for start, rate in buckets.items():
        if rate > cutoff and sigma > 0:
            exceeded = (rate - mu) / sigma if sigma else 0.0
            findings.append(
                BurstFinding(
                    window_start=start,
                    window_end=start + timedelta(minutes=window_minutes),
                    delete_rate=float(rate),
                    baseline_mean=mu,
                    baseline_std=sigma,
                    sigma_exceeded=exceeded,
                    severity=min(0.5 + exceeded * 0.1, 1.0),
                )
            )
    return findings


# ─────────────────────────────────────────────────────
# B. Log Silence Detection
# ─────────────────────────────────────────────────────

def detect_log_silence(
    system_uptime_hours: float,
    log_events: List[TimelineEvent],
    expected_event_rate_per_hour: float,
) -> tuple[bool, Optional[str]]:
    """
    Compare expected log volume to actual.
    Returns (detected: bool, detail: str | None)
    """
    if not log_events:
        return True, "No log events found at all for reported uptime."

    # Sort events
    sorted_evts = sorted(log_events, key=lambda e: e.timestamp)
    first_ts = sorted_evts[0].timestamp
    last_ts = sorted_evts[-1].timestamp
    logged_hours = (last_ts - first_ts).total_seconds() / 3600.0

    # Gap between logged period and system uptime
    if system_uptime_hours > 0 and logged_hours < system_uptime_hours * 0.5:
        coverage_pct = (logged_hours / system_uptime_hours) * 100
        return True, (
            f"System uptime={system_uptime_hours:.1f}h, "
            f"log coverage={logged_hours:.1f}h ({coverage_pct:.0f}%). "
            f"Possible log clearing or disabling during {system_uptime_hours - logged_hours:.1f}h window."
        )

    # Check event density
    expected_events = system_uptime_hours * expected_event_rate_per_hour
    actual_events = len(log_events)
    if actual_events < expected_events * 0.3:
        return True, (
            f"Expected ≈{expected_events:.0f} events, observed {actual_events}. "
            f"Event density too low — possible selective log clearing."
        )

    return False, None


# ─────────────────────────────────────────────────────
# Engine Entry Point
# ─────────────────────────────────────────────────────

def analyze_behavioral_anomalies(
    deletion_events: List[DeletionEvent],
    sigma_threshold: float,
    window_minutes: int,
    system_uptime_hours: float,
    log_events: List[TimelineEvent],
    expected_event_rate_per_hour: float,
) -> BehavioralAnalysisResponse:
    burst_findings = detect_deletion_bursts(deletion_events, sigma_threshold, window_minutes)
    silence_detected, silence_detail = detect_log_silence(
        system_uptime_hours, log_events, expected_event_rate_per_hour
    )

    return BehavioralAnalysisResponse(
        burst_findings=burst_findings,
        log_silence_detected=silence_detected,
        log_silence_details=silence_detail,
        category=DetectionCategory.BEHAVIORAL,
    )
