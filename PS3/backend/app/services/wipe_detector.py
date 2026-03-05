"""
Wipe Detector — Phase 3: Enhanced Wipe Detection Logic.

Analyses a single cluster's raw content against the Phase-2 data maps
and applies the 5-rule suspicion scoring engine defined in the
implementation plan.

Rule Engine Summary
───────────────────
Rule 1 — Safe zero space          → score = 0
  Unallocated + zero entropy + 0x00 dominant + not in history

Rule 2 — Historical zero wipe     → score = 70  (STRONG signal)
  zero_fill verdict + cluster in history + currently unallocated

Rule 3 — USN confirmation boost   → +20
  File linked to USN events: DATA_OVERWRITE / FILE_DELETE / DATA_TRUNCATION
  near image acquisition time

Rule 4 — LogFile confirmation     → +10  (optional)
  logfile_events[cluster] has DEALLOCATED + verdict == zero_fill

Rule 5 — Non-zero wipe pattern    → score = 95–100  (DEFINITIVE)
  Unallocated + one_fill / random_overwrite / multi_pass

Wipe Pattern Detection
──────────────────────
patterns: zero_fill, one_fill, random_overwrite, multi_pass, mixed, none
Uses Shannon entropy + dominant byte frequency + byte distribution
analysis on the raw cluster content.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any

from loguru import logger


# ═══════════════════════════════════════════════════════════════════════════
# Pattern classification thresholds
# ═══════════════════════════════════════════════════════════════════════════

ENTROPY_ZERO_THRESHOLD   = 0.05   # near-0 entropy → single-byte fill
ENTROPY_RANDOM_THRESHOLD = 7.5    # high entropy → random/crypto data
DOMINANT_BYTE_THRESHOLD  = 0.98   # fraction to call "single-byte fill"
MULTI_PASS_MIN_PATTERNS  = 2      # distinct fill-byte patterns to flag multi-pass

# Wipe pattern identifiers
PATTERN_ZERO_FILL        = "zero_fill"          # 0x00 × N
PATTERN_ONE_FILL         = "one_fill"           # 0xFF × N
PATTERN_RANDOM           = "random_overwrite"   # high entropy
PATTERN_MULTI_PASS       = "multi_pass"         # mixed fill + random
PATTERN_SINGLE_BYTE_FILL = "single_byte_fill"   # 0xXX × N (any single byte)
PATTERN_NONE             = "none"               # normal data

# USN reasons that strongly indicate intentional overwrite / deletion
WIPE_RELEVANT_REASONS = {"DATA_OVERWRITE", "DATA_TRUNCATION", "FILE_DELETE"}

# Max time delta between a USN event and "now" (image acquisition) to treat
# it as "recent" — we default to 180 days; callers may override
DEFAULT_RECENT_WINDOW_DAYS = 180


# ═══════════════════════════════════════════════════════════════════════════
# Low-level analysis helpers
# ═══════════════════════════════════════════════════════════════════════════

def compute_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0–8 scale)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def dominant_byte_fraction(data: bytes) -> tuple[int, float]:
    """Return (dominant_byte, fraction_of_total) for the cluster content."""
    if not data:
        return 0, 0.0
    counts = Counter(data)
    most_common_byte, most_common_count = counts.most_common(1)[0]
    return most_common_byte, most_common_count / len(data)


def detect_wipe_pattern(data: bytes) -> Dict[str, Any]:
    """
    Classify the wipe pattern (if any) for a given raw cluster.

    Returns:
        {
          "verdict":         str,      # PATTERN_* constant
          "entropy":         float,    # Shannon entropy (0–8)
          "dominant_byte":  int,       # 0–255
          "dominant_frac":  float,     # 0.0–1.0
          "byte_count":     int,
          "distinct_bytes": int,
        }
    """
    if not data:
        return {
            "verdict": PATTERN_NONE,
            "entropy": 0.0,
            "dominant_byte": 0,
            "dominant_frac": 0.0,
            "byte_count": 0,
            "distinct_bytes": 0,
        }

    entropy               = compute_entropy(data)
    dom_byte, dom_frac    = dominant_byte_fraction(data)
    distinct_bytes        = len(set(data))

    # ── Rule precedence ──────────────────────────────────────────────────
    if dom_frac >= DOMINANT_BYTE_THRESHOLD:
        if dom_byte == 0x00:
            verdict = PATTERN_ZERO_FILL
        elif dom_byte == 0xFF:
            verdict = PATTERN_ONE_FILL
        else:
            verdict = PATTERN_SINGLE_BYTE_FILL
    elif entropy >= ENTROPY_RANDOM_THRESHOLD:
        verdict = PATTERN_RANDOM
    elif entropy <= ENTROPY_ZERO_THRESHOLD:
        # Low entropy but not dominated by one byte — unusual
        verdict = PATTERN_ZERO_FILL
    else:
        # Check for multi-pass: moderate entropy but structured byte distribution
        # Heuristic: multiple fill bytes each appearing in large blocks
        counts = Counter(data)
        top_bytes = counts.most_common(5)
        # If top 3 bytes together cover > 70% and entropy is moderate
        top3_frac = sum(c for _, c in top_bytes[:3]) / len(data)
        if top3_frac > 0.70 and entropy < 3.0:
            verdict = PATTERN_MULTI_PASS
        else:
            verdict = PATTERN_NONE

    return {
        "verdict":        verdict,
        "entropy":        round(entropy, 4),
        "dominant_byte":  dom_byte,
        "dominant_frac":  round(dom_frac, 4),
        "byte_count":     len(data),
        "distinct_bytes": distinct_bytes,
    }


# ═══════════════════════════════════════════════════════════════════════════
# 5-Rule Suspicion Scoring Engine
# ═══════════════════════════════════════════════════════════════════════════

def analyze_cluster(
    cluster_number:      int,
    cluster_data:        bytes,
    allocation_map:      Dict[int, bool],
    cluster_history_map: Dict[int, Dict],
    usn_map:             Dict[int, List[Dict]],
    logfile_events:      Dict[int, List[str]],
    acquisition_time:    Optional[datetime] = None,
    recent_window_days:  int = DEFAULT_RECENT_WINDOW_DAYS,
) -> Dict[str, Any]:
    """
    Apply the 5-rule suspicion engine to a single cluster.

    Parameters
    ----------
    cluster_number       : LCN (logical cluster number)
    cluster_data         : raw bytes of the cluster (bytes_per_cluster length)
    allocation_map       : from ntfs_parser.parse_bitmap()
    cluster_history_map  : from ntfs_parser.parse_mft()
    usn_map              : from ntfs_parser.parse_usn_journal()
    logfile_events       : from ntfs_parser.parse_logfile()
    acquisition_time     : datetime of image acquisition (UTC); defaults to now
    recent_window_days   : USN events within this window count as "recent"

    Returns
    -------
    Full analysis dict (see wipe_cross_reference.crossref_cluster for the
    combined output including confidence_level).
    """
    if acquisition_time is None:
        acquisition_time = datetime.now(tz=timezone.utc)

    # ── Step 1: pattern detection ─────────────────────────────────────────
    pattern_info = detect_wipe_pattern(cluster_data)
    verdict      = pattern_info["verdict"]
    entropy      = pattern_info["entropy"]

    # ── Step 2: look up supporting maps ──────────────────────────────────
    currently_allocated = allocation_map.get(cluster_number, False)
    history_entry       = cluster_history_map.get(cluster_number)
    in_history          = history_entry is not None

    # Resolve USN events via history → file_reference
    usn_events: List[Dict] = []
    if in_history:
        file_ref = history_entry.get("file_reference")
        if file_ref is not None:
            usn_events = usn_map.get(file_ref, [])

    logfile_ev = logfile_events.get(cluster_number, [])

    # ── Step 3: five-rule scoring ─────────────────────────────────────────
    suspicion_score = 0
    rules_triggered: List[str] = []

    # ─── Rule 1 — Safe Zero Space ────────────────────────────────────────
    if (
        not currently_allocated
        and verdict == PATTERN_ZERO_FILL
        and entropy <= ENTROPY_ZERO_THRESHOLD
        and not in_history
    ):
        suspicion_score = 0
        rules_triggered.append("Rule1:SafeZeroSpace")
        # Short-circuit — natural empty space, no further rules needed
        return _build_result(
            cluster_number, currently_allocated, history_entry,
            usn_events, logfile_ev, pattern_info,
            suspicion_score, rules_triggered
        )

    # ─── Rule 2 — Historical Zero Wipe ───────────────────────────────────
    if (
        verdict == PATTERN_ZERO_FILL
        and in_history
        and not currently_allocated
    ):
        suspicion_score = 70
        rules_triggered.append("Rule2:HistoricalZeroWipe(+70)")

    # ─── Rule 3 — USN Confirmation Boost ─────────────────────────────────
    if usn_events:
        recent_cutoff = acquisition_time - timedelta(days=recent_window_days)
        for ev in usn_events:
            ev_ts = ev.get("timestamp")
            # Acceptable if timestamp is None (journal entries without ts)
            is_recent = (
                ev_ts is None
                or (ev_ts >= recent_cutoff)
            )
            reason_flags = ev.get("reason_flags", [])
            has_wipe_reason = bool(
                set(reason_flags) & WIPE_RELEVANT_REASONS
            )
            if is_recent and has_wipe_reason:
                suspicion_score += 20
                rules_triggered.append(
                    f"Rule3:USNBoost(+20) [{','.join(set(reason_flags) & WIPE_RELEVANT_REASONS)}]"
                )
                break  # one boost per cluster

    # ─── Rule 4 — LogFile Confirmation ───────────────────────────────────
    if (
        "DEALLOCATED" in logfile_ev
        and verdict == PATTERN_ZERO_FILL
    ):
        suspicion_score += 10
        rules_triggered.append("Rule4:LogFileConfirm(+10)")

    # ─── Rule 5 — Non-Zero Wipe Pattern in Unallocated ───────────────────
    DEFINITIVE_WIPE_PATTERNS = {
        PATTERN_ONE_FILL,
        PATTERN_RANDOM,
        PATTERN_MULTI_PASS,
        PATTERN_SINGLE_BYTE_FILL,
    }
    if not currently_allocated and verdict in DEFINITIVE_WIPE_PATTERNS:
        if verdict == PATTERN_RANDOM:
            suspicion_score = 100
        elif verdict == PATTERN_MULTI_PASS:
            suspicion_score = 98
        elif verdict == PATTERN_ONE_FILL:
            suspicion_score = 95
        else:
            suspicion_score = 90  # single_byte_fill
        rules_triggered.append(
            f"Rule5:NonZeroWipeInUnalloc({verdict}→score={suspicion_score})"
        )

    # ── Cap score at 100 ─────────────────────────────────────────────────
    suspicion_score = min(suspicion_score, 100)

    return _build_result(
        cluster_number, currently_allocated, history_entry,
        usn_events, logfile_ev, pattern_info,
        suspicion_score, rules_triggered
    )


def _build_result(
    cluster_number:     int,
    currently_allocated:bool,
    history_entry:      Optional[Dict],
    usn_events:         List[Dict],
    logfile_events_for: List[str],
    pattern_info:       Dict,
    suspicion_score:    int,
    rules_triggered:    List[str],
) -> Dict[str, Any]:
    """Assemble the per-cluster result dict."""
    if suspicion_score >= 80:
        confidence = "HIGH"
    elif suspicion_score >= 50:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # Summarise wipe-relevant USN event reasons
    wipe_usn_reasons = []
    for ev in usn_events:
        flags = ev.get("reason_flags", [])
        relevant = [f for f in flags if f in WIPE_RELEVANT_REASONS]
        wipe_usn_reasons.extend(relevant)

    return {
        "cluster":             cluster_number,
        "current_allocated":   currently_allocated,
        "previous_owner":      history_entry["filename"] if history_entry else None,
        "file_reference":      history_entry["file_reference"] if history_entry else None,
        "usn_events":          wipe_usn_reasons,
        "logfile_events":      logfile_events_for,
        "wipe_pattern":        pattern_info["verdict"],
        "entropy":             pattern_info["entropy"],
        "dominant_byte":       pattern_info["dominant_byte"],
        "dominant_frac":       pattern_info["dominant_frac"],
        "suspicion_score":     suspicion_score,
        "confidence_level":    confidence,
        "rules_triggered":     rules_triggered,
        "timestamps":          history_entry.get("timestamps") if history_entry else None,
    }
