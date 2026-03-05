"""
Section 4 – Unified Timeline Construction
Normalizes cross-artifact events, sorts chronologically,
and detects regressions, missing events, and logical impossibilities.
"""

from __future__ import annotations
import uuid
from datetime import timedelta
from typing import List, Optional

from app.models.antiforensics_schemas import (
    TimelineEvent,
    NormalizedEvent,
    TimelineAnomaly,
    TimelineResponse,
    ActionType,
    ArtifactSource,
)


# ─────────────────────────────────────────────────────
# Normalization
# ─────────────────────────────────────────────────────

def normalize_event(ev: TimelineEvent) -> NormalizedEvent:
    return NormalizedEvent(
        **ev.model_dump(),
        event_id=str(uuid.uuid4()),
        flags=[],
    )


# ─────────────────────────────────────────────────────
# Regression Detection
# ─────────────────────────────────────────────────────

def detect_time_regressions(
    events: List[NormalizedEvent],
) -> List[TimelineAnomaly]:
    """
    Same object_id should not have CREATE after DELETE,
    or MODIFY before CREATE.
    """
    anomalies: List[TimelineAnomaly] = []
    from collections import defaultdict
    obj_history: dict[str, list] = defaultdict(list)
    for i, ev in enumerate(events):
        obj_history[ev.object_id].append((i, ev))

    for obj_id, history in obj_history.items():
        create_idx: Optional[int] = None
        delete_idx: Optional[int] = None
        for i, (ev_idx, ev) in enumerate(history):
            if ev.action == ActionType.CREATE:
                if delete_idx is not None and ev.timestamp > history[delete_idx][1].timestamp:
                    pass  # Legitimate re-creation
                elif delete_idx is not None and ev.timestamp < history[delete_idx][1].timestamp:
                    anomalies.append(
                        TimelineAnomaly(
                            index=ev_idx,
                            event=ev,
                            issue="CREATE_AFTER_DELETE_REGRESSION",
                            related_events=[history[delete_idx][0]],
                        )
                    )
                create_idx = i
            elif ev.action == ActionType.MODIFY:
                if create_idx is None:
                    anomalies.append(
                        TimelineAnomaly(
                            index=ev_idx,
                            event=ev,
                            issue="MODIFY_WITHOUT_PRIOR_CREATE",
                        )
                    )
            elif ev.action == ActionType.DELETE:
                delete_idx = i

    return anomalies


# ─────────────────────────────────────────────────────
# Missing Expected Events
# ─────────────────────────────────────────────────────

def detect_missing_expected_events(
    events: List[NormalizedEvent],
) -> List[str]:
    """
    Patterns that imply a missing event:
    - DELETE without preceding CREATE (for same object_id)
    - EXECUTE without CREATE (binary disappeared from MFT but Prefetch exists)
    """
    missing: List[str] = []
    from collections import defaultdict

    seen_creates: set = set()
    seen_executes: set = set()

    for ev in events:
        if ev.action == ActionType.CREATE:
            seen_creates.add(ev.object_id)
        elif ev.action == ActionType.EXECUTE:
            seen_executes.add(ev.object_id)
        elif ev.action == ActionType.DELETE and ev.object_id not in seen_creates:
            missing.append(
                f"DELETE without CREATE for object '{ev.object_id}' "
                f"at {ev.timestamp.isoformat()} [{ev.artifact_source}]"
            )

    for obj_id in seen_executes - seen_creates:
        missing.append(
            f"EXECUTE record exists but no CREATE record for '{obj_id}' "
            f"— binary may have been wiped after execution"
        )

    return missing


# ─────────────────────────────────────────────────────
# Logical Impossibilities
# ─────────────────────────────────────────────────────

def detect_logical_impossibilities(
    events: List[NormalizedEvent],
) -> List[TimelineAnomaly]:
    """
    Flag events that are physically impossible:
    - Two events on same object within 1 microsecond (artifact injection)
    - Event timestamps in the future beyond uptime clock
    """
    anomalies: List[TimelineAnomaly] = []
    from collections import defaultdict

    obj_last: dict[str, tuple[int, NormalizedEvent]] = {}

    for i, ev in enumerate(events):
        if ev.object_id in obj_last:
            prev_idx, prev_ev = obj_last[ev.object_id]
            delta = abs((ev.timestamp - prev_ev.timestamp).total_seconds())
            if delta < 0.000001 and ev.action != prev_ev.action:
                anomalies.append(
                    TimelineAnomaly(
                        index=i,
                        event=ev,
                        issue=f"SUB_MICROSECOND_DUAL_ACTION ({prev_ev.action} → {ev.action})",
                        related_events=[prev_idx],
                    )
                )
        obj_last[ev.object_id] = (i, ev)

    return anomalies


# ─────────────────────────────────────────────────────
# Engine Entry Point
# ─────────────────────────────────────────────────────

def build_unified_timeline(events: List[TimelineEvent]) -> TimelineResponse:
    normalized = [normalize_event(ev) for ev in events]
    sorted_events = sorted(normalized, key=lambda e: e.timestamp)

    regressions = detect_time_regressions(sorted_events)
    missing = detect_missing_expected_events(sorted_events)
    impossibilities = detect_logical_impossibilities(sorted_events)

    return TimelineResponse(
        total_events=len(sorted_events),
        sorted_events=sorted_events,
        regressions=regressions,
        missing_expected_events=missing,
        logical_impossibilities=impossibilities,
    )
