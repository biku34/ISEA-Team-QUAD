"""
Shared Pydantic models for the Anti-Forensics Detection Engine.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────

class ArtifactSource(str, Enum):
    MFT = "MFT"
    USN_JOURNAL = "USN_JOURNAL"
    LOG_FILE = "LOG_FILE"
    PREFETCH = "PREFETCH"
    EVENT_LOG = "EVENT_LOG"
    AMCACHE = "AMCACHE"
    SHIMCACHE = "SHIMCACHE"
    REGISTRY = "REGISTRY"
    SRUM = "SRUM"
    SHADOW_COPY = "SHADOW_COPY"


class DetectionCategory(str, Enum):
    TEMPORAL = "Temporal Inconsistency"
    STRUCTURAL = "Structural Inconsistency"
    STATISTICAL = "Statistical Anomaly"
    CROSS_ARTIFACT = "Cross-Artifact Conflict"
    BEHAVIORAL = "Abrupt Behavioral Change"


class SuspicionLevel(str, Enum):
    NORMAL = "Normal"
    SUSPICIOUS = "Suspicious"
    STRONG = "Strong Anti-Forensic Activity"
    HIGH_CONFIDENCE = "High Confidence Anti-Forensic"


class ActionType(str, Enum):
    CREATE = "CREATE"
    MODIFY = "MODIFY"
    DELETE = "DELETE"
    RENAME = "RENAME"
    EXECUTE = "EXECUTE"
    WIPE = "WIPE"
    LOG_CLEAR = "LOG_CLEAR"
    SHADOW_DELETE = "SHADOW_DELETE"


# ─────────────────────────────────────────────
# Base Event / Timeline Models
# ─────────────────────────────────────────────

class TimelineEvent(BaseModel):
    timestamp: datetime
    artifact_source: ArtifactSource
    object_id: str = Field(..., description="File path, entry number, or unique identifier")
    action: ActionType
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="0.0 – 1.0")
    metadata: Optional[Dict[str, Any]] = None


class NormalizedEvent(TimelineEvent):
    event_id: str = Field(..., description="UUID for this event")
    flags: List[str] = Field(default_factory=list, description="Raised detection flags")


# ─────────────────────────────────────────────
# MFT / Timestamp Models
# ─────────────────────────────────────────────

class MFTTimestamps(BaseModel):
    created: datetime
    modified: datetime
    accessed: datetime
    record_changed: datetime


class USNEntry(BaseModel):
    usn: int = Field(..., description="USN sequence number")
    timestamp: datetime
    filename: str
    reason: str
    file_reference: str


class LogFileEntry(BaseModel):
    lsn: int = Field(..., description="Log Sequence Number")
    timestamp: datetime
    redo_operation: str
    undo_operation: str
    transaction_id: int


class PrefetchEntry(BaseModel):
    executable: str
    last_run: datetime
    run_count: int
    volume_path: str


# ─────────────────────────────────────────────
# Temporal Inconsistency
# ─────────────────────────────────────────────

class TimeVector(BaseModel):
    filename: str
    mft_create: Optional[datetime] = None
    mft_modify: Optional[datetime] = None
    mft_access: Optional[datetime] = None
    mft_record_change: Optional[datetime] = None
    usn_first: Optional[datetime] = None
    usn_last: Optional[datetime] = None
    logfile_create: Optional[datetime] = None
    prefetch_last_run: Optional[datetime] = None


class TemporalAnalysisRequest(BaseModel):
    time_vectors: List[TimeVector]


class TemporalFinding(BaseModel):
    filename: str
    rule_triggered: str
    description: str
    conflicting_artifacts: List[str]
    severity: float = Field(..., ge=0.0, le=1.0)


class TemporalAnalysisResponse(BaseModel):
    total_files: int
    flagged_files: int
    findings: List[TemporalFinding]
    category: DetectionCategory = DetectionCategory.TEMPORAL


# ─────────────────────────────────────────────
# Sequence Integrity
# ─────────────────────────────────────────────

class USNSequenceRequest(BaseModel):
    entries: List[USNEntry]
    dynamic_threshold_multiplier: float = Field(default=3.0, description="Multiplier for gap detection")


class LSNSequenceRequest(BaseModel):
    entries: List[LogFileEntry]


class SequenceFinding(BaseModel):
    index: int
    usn_or_lsn: int
    expected_approx: Optional[int]
    issue: str
    severity: float


class SequenceIntegrityResponse(BaseModel):
    total_entries: int
    regressions: List[SequenceFinding]
    gaps: List[SequenceFinding]
    incomplete_transactions: List[SequenceFinding]
    category: DetectionCategory = DetectionCategory.STRUCTURAL


# ─────────────────────────────────────────────
# Behavioral / Burst Detection
# ─────────────────────────────────────────────

class DeletionEvent(BaseModel):
    timestamp: datetime
    filename: str
    size_bytes: Optional[int] = None


class BurstDetectionRequest(BaseModel):
    deletion_events: List[DeletionEvent]
    sigma_threshold: float = Field(default=3.0, description="Number of std devs for anomaly")
    window_minutes: int = Field(default=1, description="Bucket window in minutes")


class LogSilenceRequest(BaseModel):
    system_uptime_hours: float
    log_events: List[TimelineEvent]
    expected_event_rate_per_hour: float = Field(default=10.0)


class BurstFinding(BaseModel):
    window_start: datetime
    window_end: datetime
    delete_rate: float
    baseline_mean: float
    baseline_std: float
    sigma_exceeded: float
    severity: float


class BehavioralAnalysisResponse(BaseModel):
    burst_findings: List[BurstFinding]
    log_silence_detected: bool
    log_silence_details: Optional[str]
    category: DetectionCategory = DetectionCategory.BEHAVIORAL


# ─────────────────────────────────────────────
# Entropy / Wipe Detection
# ─────────────────────────────────────────────

class ClusterData(BaseModel):
    cluster_id: int
    offset: int
    raw_bytes_hex: str = Field(..., description="Hex-encoded cluster bytes")


class EntropyAnalysisRequest(BaseModel):
    clusters: List[ClusterData]
    high_entropy_threshold: float = Field(default=7.8, description="Shannon entropy threshold for random overwrite")
    zero_threshold: float = Field(default=0.1, description="Entropy threshold for zero wipe")


class ClusterEntropyResult(BaseModel):
    cluster_id: int
    offset: int
    entropy: float
    wipe_type: Optional[str] = None  # "random", "zero", "pattern", None
    pattern_detected: Optional[str] = None


class EntropyAnalysisResponse(BaseModel):
    total_clusters: int
    random_overwrite_clusters: int
    zero_overwrite_clusters: int
    pattern_wipe_clusters: int
    results: List[ClusterEntropyResult]
    secure_wipe_detected: bool
    category: DetectionCategory = DetectionCategory.STATISTICAL


# ─────────────────────────────────────────────
# MFT Structural Integrity
# ─────────────────────────────────────────────

class MFTEntry(BaseModel):
    entry_number: int
    filename: str
    parent_entry_number: int
    is_deleted: bool
    sequence_number: int
    timestamps: MFTTimestamps
    logfile_lsn: Optional[int] = None


class MFTIntegrityRequest(BaseModel):
    mft_entries: List[MFTEntry]
    usn_entries: List[USNEntry]
    logfile_entries: Optional[List[LogFileEntry]] = None


class MFTFinding(BaseModel):
    entry_number: int
    filename: str
    issue: str
    details: str
    severity: float


class MFTIntegrityResponse(BaseModel):
    total_entries: int
    reuse_anomalies: List[MFTFinding]
    parent_child_conflicts: List[MFTFinding]
    category: DetectionCategory = DetectionCategory.STRUCTURAL


# ─────────────────────────────────────────────
# Shadow Copy Tampering
# ─────────────────────────────────────────────

class ShadowCopyEvent(BaseModel):
    timestamp: datetime
    event_id: int
    description: str
    source: str


class ShadowCopyRequest(BaseModel):
    event_log_entries: List[ShadowCopyEvent]
    prefetch_entries: Optional[List[PrefetchEntry]] = None
    restore_points: Optional[List[datetime]] = None
    burst_findings: Optional[List[BurstFinding]] = None


class ShadowCopyFinding(BaseModel):
    timestamp: datetime
    indicator: str
    evidence: List[str]
    chain_detected: bool
    severity: float


class ShadowCopyResponse(BaseModel):
    vss_deletion_events: int
    vssadmin_prefetch_found: bool
    missing_restore_points: int
    anti_forensic_chain_detected: bool
    findings: List[ShadowCopyFinding]
    category: DetectionCategory = DetectionCategory.BEHAVIORAL


# ─────────────────────────────────────────────
# Unified Timeline
# ─────────────────────────────────────────────

class TimelineRequest(BaseModel):
    events: List[TimelineEvent]


class TimelineAnomaly(BaseModel):
    index: int
    event: TimelineEvent
    issue: str
    related_events: Optional[List[int]] = None


class TimelineResponse(BaseModel):
    total_events: int
    sorted_events: List[NormalizedEvent]
    regressions: List[TimelineAnomaly]
    missing_expected_events: List[str]
    logical_impossibilities: List[TimelineAnomaly]


# ─────────────────────────────────────────────
# Suspicion Scoring
# ─────────────────────────────────────────────

class ScoringInput(BaseModel):
    timestamp_inconsistencies: int = 0
    journal_gaps: int = 0
    logs_cleared: bool = False
    shadow_copies_deleted: bool = False
    burst_deletions: int = 0
    high_entropy_wipes: int = 0
    mft_reuse_anomalies: int = 0
    # Optional raw confidence multipliers (0.0 – 1.0)
    timestamp_confidence: float = 1.0
    journal_confidence: float = 1.0
    log_confidence: float = 1.0
    shadow_confidence: float = 1.0
    burst_confidence: float = 1.0
    entropy_confidence: float = 1.0
    mft_confidence: float = 1.0


class ScoringResponse(BaseModel):
    breakdown: Dict[str, float]
    total_score: float
    level: SuspicionLevel
    recommendation: str


# ─────────────────────────────────────────────
# Graph Correlation
# ─────────────────────────────────────────────

class GraphNode(BaseModel):
    node_id: str
    node_type: str  # "file", "process", "volume", "log"
    label: str
    metadata: Optional[Dict[str, Any]] = None


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: ActionType
    timestamp: datetime
    weight: float = 1.0


class GraphRequest(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class SuspiciousSubgraph(BaseModel):
    subgraph_id: str
    central_node: str
    involved_nodes: List[str]
    pattern: str
    severity: float
    evidence: List[str]


class GraphResponse(BaseModel):
    total_nodes: int
    total_edges: int
    suspicious_subgraphs: List[SuspiciousSubgraph]
    anti_forensic_clusters: int
    summary: str
