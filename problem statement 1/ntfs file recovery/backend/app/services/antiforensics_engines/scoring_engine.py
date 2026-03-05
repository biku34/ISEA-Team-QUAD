"""
Section 5 – Suspicion Scoring Model
Weighted scoring system across all detection indicators.
"""

from __future__ import annotations
from typing import Dict

from app.models.antiforensics_schemas import (
    ScoringInput,
    ScoringResponse,
    SuspicionLevel,
)

# ─────────────────────────────────────────────────────
# Weight Table (from specification)
# ─────────────────────────────────────────────────────

WEIGHTS: Dict[str, float] = {
    "timestamp_inconsistency": 5.0,
    "journal_gap":             4.0,
    "log_cleared":             4.0,
    "shadow_copy_deleted":     4.0,
    "burst_deletion":          3.0,
    "high_entropy_wipe":       5.0,
    "mft_reuse_anomaly":       3.0,
}

# ─────────────────────────────────────────────────────
# Threshold → Level mapping
# ─────────────────────────────────────────────────────

def _score_to_level(score: float) -> SuspicionLevel:
    if score <= 5:
        return SuspicionLevel.NORMAL
    elif score <= 10:
        return SuspicionLevel.SUSPICIOUS
    elif score <= 20:
        return SuspicionLevel.STRONG
    else:
        return SuspicionLevel.HIGH_CONFIDENCE


def _recommendation(level: SuspicionLevel) -> str:
    return {
        SuspicionLevel.NORMAL: (
            "No significant anti-forensic indicators detected. "
            "Continue standard evidence preservation."
        ),
        SuspicionLevel.SUSPICIOUS: (
            "Moderate indicators present. Preserve all artifacts immediately. "
            "Conduct targeted review of flagged timestamps and journal gaps."
        ),
        SuspicionLevel.STRONG: (
            "Strong anti-forensic activity detected. Escalate immediately. "
            "Full forensic acquisition recommended. Do not power off the system. "
            "Capture volatile memory before further analysis."
        ),
        SuspicionLevel.HIGH_CONFIDENCE: (
            "HIGH CONFIDENCE: Multiple coordinated anti-forensic techniques detected. "
            "This is likely a deliberate cover-up. Treat this as a critical incident. "
            "Preserve chain of custody, perform full disk imaging, and escalate to senior analysts."
        ),
    }[level]


# ─────────────────────────────────────────────────────
# Engine Entry Point
# ─────────────────────────────────────────────────────

def compute_suspicion_score(inp: ScoringInput) -> ScoringResponse:
    breakdown: Dict[str, float] = {}

    # Each indicator: weight × count_or_bool × confidence
    breakdown["timestamp_inconsistency"] = (
        WEIGHTS["timestamp_inconsistency"]
        * inp.timestamp_inconsistencies
        * inp.timestamp_confidence
    )
    breakdown["journal_gap"] = (
        WEIGHTS["journal_gap"]
        * inp.journal_gaps
        * inp.journal_confidence
    )
    breakdown["log_cleared"] = (
        WEIGHTS["log_cleared"]
        * (1 if inp.logs_cleared else 0)
        * inp.log_confidence
    )
    breakdown["shadow_copy_deleted"] = (
        WEIGHTS["shadow_copy_deleted"]
        * (1 if inp.shadow_copies_deleted else 0)
        * inp.shadow_confidence
    )
    breakdown["burst_deletion"] = (
        WEIGHTS["burst_deletion"]
        * inp.burst_deletions
        * inp.burst_confidence
    )
    breakdown["high_entropy_wipe"] = (
        WEIGHTS["high_entropy_wipe"]
        * inp.high_entropy_wipes
        * inp.entropy_confidence
    )
    breakdown["mft_reuse_anomaly"] = (
        WEIGHTS["mft_reuse_anomaly"]
        * inp.mft_reuse_anomalies
        * inp.mft_confidence
    )

    total = sum(breakdown.values())
    level = _score_to_level(total)

    return ScoringResponse(
        breakdown={k: round(v, 2) for k, v in breakdown.items()},
        total_score=round(total, 2),
        level=level,
        recommendation=_recommendation(level),
    )
