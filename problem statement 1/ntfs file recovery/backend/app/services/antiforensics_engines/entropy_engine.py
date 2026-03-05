"""
3.4 Entropy & Wipe Detection Engine
Computes Shannon entropy per cluster and identifies random, zero, and pattern overwrites.
"""

from __future__ import annotations
import math
from collections import Counter
from typing import List, Optional, Tuple

from app.models.antiforensics_schemas import (
    ClusterData,
    ClusterEntropyResult,
    EntropyAnalysisResponse,
    DetectionCategory,
)


# ─────────────────────────────────────────────────────
# Core Shannon Entropy
# ─────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """
    H = -Σ p(x) · log₂ p(x)
    Max value = 8.0 bits for truly random data.
    """
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


# ─────────────────────────────────────────────────────
# Pattern Detection
# ─────────────────────────────────────────────────────

def _detect_repeating_pattern(data: bytes, max_period: int = 32) -> Optional[str]:
    """
    Check if data is a repetition of a short byte sequence.
    Returns the hex pattern string or None.
    """
    if len(data) < 2:
        return None
    for period in range(1, min(max_period + 1, len(data) // 2)):
        pattern = data[:period]
        if data == pattern * (len(data) // period) + pattern[: len(data) % period]:
            return pattern.hex()
    return None


# ─────────────────────────────────────────────────────
# Single Cluster Classifier
# ─────────────────────────────────────────────────────

def classify_cluster(
    cluster: ClusterData,
    high_entropy_threshold: float,
    zero_threshold: float,
) -> ClusterEntropyResult:
    try:
        raw = bytes.fromhex(cluster.raw_bytes_hex)
    except ValueError:
        return ClusterEntropyResult(
            cluster_id=cluster.cluster_id,
            offset=cluster.offset,
            entropy=0.0,
            wipe_type="PARSE_ERROR",
        )

    entropy = shannon_entropy(raw)
    wipe_type: Optional[str] = None
    pattern: Optional[str] = None

    if entropy <= zero_threshold:
        # All zeros or uniform byte
        wipe_type = "zero" if set(raw) == {0} else "uniform_byte"
    elif entropy >= high_entropy_threshold:
        # Check pattern before calling it random
        pat = _detect_repeating_pattern(raw)
        if pat:
            wipe_type = "pattern"
            pattern = pat
        else:
            wipe_type = "random"
    else:
        # Mid-range entropy — check for repeating pattern anyway
        pat = _detect_repeating_pattern(raw)
        if pat:
            wipe_type = "pattern"
            pattern = pat

    return ClusterEntropyResult(
        cluster_id=cluster.cluster_id,
        offset=cluster.offset,
        entropy=round(entropy, 4),
        wipe_type=wipe_type,
        pattern_detected=pattern,
    )


# ─────────────────────────────────────────────────────
# Engine Entry Point
# ─────────────────────────────────────────────────────

def analyze_entropy(
    clusters: List[ClusterData],
    high_entropy_threshold: float,
    zero_threshold: float,
) -> EntropyAnalysisResponse:
    results = [classify_cluster(c, high_entropy_threshold, zero_threshold) for c in clusters]

    random_count = sum(1 for r in results if r.wipe_type == "random")
    zero_count = sum(1 for r in results if r.wipe_type in ("zero", "uniform_byte"))
    pattern_count = sum(1 for r in results if r.wipe_type == "pattern")

    # Secure wipe detected if multiple consecutive clusters share wipe characteristics
    secure_wipe = (random_count + zero_count + pattern_count) >= max(2, len(clusters) * 0.3)

    return EntropyAnalysisResponse(
        total_clusters=len(clusters),
        random_overwrite_clusters=random_count,
        zero_overwrite_clusters=zero_count,
        pattern_wipe_clusters=pattern_count,
        results=results,
        secure_wipe_detected=secure_wipe,
        category=DetectionCategory.STATISTICAL,
    )
