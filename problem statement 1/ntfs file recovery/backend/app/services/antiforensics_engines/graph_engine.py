"""
Section 6 – Graph-Based Correlation Engine
Builds a directed graph of system activity and detects
anti-forensic subgraphs / clusters.
"""

from __future__ import annotations
import uuid
from collections import defaultdict
from typing import Dict, List, Set

from app.models.antiforensics_schemas import (
    GraphNode,
    GraphEdge,
    SuspiciousSubgraph,
    GraphResponse,
    ActionType,
)


# ─────────────────────────────────────────────────────
# Graph Representation (pure Python, no networkx dep)
# ─────────────────────────────────────────────────────

class InMemoryGraph:
    def __init__(self, nodes: List[GraphNode], edges: List[GraphEdge]):
        self.nodes: Dict[str, GraphNode] = {n.node_id: n for n in nodes}
        self.out_edges: Dict[str, List[GraphEdge]] = defaultdict(list)
        self.in_edges: Dict[str, List[GraphEdge]] = defaultdict(list)
        for edge in edges:
            self.out_edges[edge.source].append(edge)
            self.in_edges[edge.target].append(edge)

    def outgoing(self, node_id: str) -> List[GraphEdge]:
        return self.out_edges.get(node_id, [])

    def incoming(self, node_id: str) -> List[GraphEdge]:
        return self.in_edges.get(node_id, [])


# ─────────────────────────────────────────────────────
# Pattern Matchers
# ─────────────────────────────────────────────────────

def _detect_mass_delete_cluster(graph: InMemoryGraph) -> List[SuspiciousSubgraph]:
    """Process node deleting many files (≥5) is suspicious."""
    findings: List[SuspiciousSubgraph] = []
    process_nodes = [n for n in graph.nodes.values() if n.node_type == "process"]

    for proc in process_nodes:
        delete_edges = [
            e for e in graph.outgoing(proc.node_id)
            if e.relationship == ActionType.DELETE
        ]
        if len(delete_edges) >= 5:
            targets = [e.target for e in delete_edges]
            findings.append(
                SuspiciousSubgraph(
                    subgraph_id=str(uuid.uuid4()),
                    central_node=proc.node_id,
                    involved_nodes=[proc.node_id] + targets,
                    pattern="MASS_FILE_DELETION",
                    severity=min(0.4 + len(delete_edges) * 0.05, 1.0),
                    evidence=[
                        f"Process '{proc.label}' deleted {len(delete_edges)} files",
                        f"Targets: {[graph.nodes[t].label for t in targets if t in graph.nodes][:5]}",
                    ],
                )
            )
    return findings


def _detect_log_clearing_cluster(graph: InMemoryGraph) -> List[SuspiciousSubgraph]:
    """Process that clears logs."""
    findings: List[SuspiciousSubgraph] = []
    for node_id, node in graph.nodes.items():
        if node.node_type != "process":
            continue
        log_clear_edges = [
            e for e in graph.outgoing(node_id)
            if e.relationship == ActionType.LOG_CLEAR
        ]
        if log_clear_edges:
            targets = [e.target for e in log_clear_edges]
            findings.append(
                SuspiciousSubgraph(
                    subgraph_id=str(uuid.uuid4()),
                    central_node=node_id,
                    involved_nodes=[node_id] + targets,
                    pattern="LOG_CLEARING",
                    severity=0.85,
                    evidence=[
                        f"Process '{node.label}' cleared {len(log_clear_edges)} log(s)",
                    ],
                )
            )
    return findings


def _detect_shadow_deletion_cluster(graph: InMemoryGraph) -> List[SuspiciousSubgraph]:
    """Process that deletes shadow copies."""
    findings: List[SuspiciousSubgraph] = []
    for node_id, node in graph.nodes.items():
        if node.node_type != "process":
            continue
        shadow_edges = [
            e for e in graph.outgoing(node_id)
            if e.relationship == ActionType.SHADOW_DELETE
        ]
        if shadow_edges:
            findings.append(
                SuspiciousSubgraph(
                    subgraph_id=str(uuid.uuid4()),
                    central_node=node_id,
                    involved_nodes=[node_id] + [e.target for e in shadow_edges],
                    pattern="SHADOW_COPY_DELETION",
                    severity=0.90,
                    evidence=[
                        f"Process '{node.label}' deleted {len(shadow_edges)} shadow copy volume(s)",
                    ],
                )
            )
    return findings


def _detect_combined_anti_forensic_cluster(
    graph: InMemoryGraph,
    individual_findings: List[SuspiciousSubgraph],
) -> List[SuspiciousSubgraph]:
    """
    If the SAME process shows mass-delete + log-clear + shadow-delete,
    that's the full anti-forensic cluster.
    """
    findings: List[SuspiciousSubgraph] = []
    from collections import Counter

    pattern_by_node: Dict[str, List[str]] = defaultdict(list)
    for f in individual_findings:
        pattern_by_node[f.central_node].append(f.pattern)

    for node_id, patterns in pattern_by_node.items():
        unique_patterns = set(patterns)
        if len(unique_patterns) >= 2:
            node = graph.nodes.get(node_id)
            label = node.label if node else node_id
            all_involved: Set[str] = {node_id}
            all_evidence: List[str] = []
            for f in individual_findings:
                if f.central_node == node_id:
                    all_involved.update(f.involved_nodes)
                    all_evidence.extend(f.evidence)

            findings.append(
                SuspiciousSubgraph(
                    subgraph_id=str(uuid.uuid4()),
                    central_node=node_id,
                    involved_nodes=list(all_involved),
                    pattern="ANTI_FORENSIC_CLUSTER",
                    severity=min(0.6 + len(unique_patterns) * 0.15, 1.0),
                    evidence=[
                        f"Process '{label}' exhibits {len(unique_patterns)} anti-forensic patterns: "
                        f"{', '.join(unique_patterns)}"
                    ] + all_evidence,
                )
            )
    return findings


# ─────────────────────────────────────────────────────
# Engine Entry Point
# ─────────────────────────────────────────────────────

def analyze_graph(nodes: List[GraphNode], edges: List[GraphEdge]) -> GraphResponse:
    graph = InMemoryGraph(nodes, edges)

    mass_delete = _detect_mass_delete_cluster(graph)
    log_clear = _detect_log_clearing_cluster(graph)
    shadow_del = _detect_shadow_deletion_cluster(graph)

    individual = mass_delete + log_clear + shadow_del
    combined = _detect_combined_anti_forensic_cluster(graph, individual)

    all_findings = individual + combined
    cluster_count = len(combined)

    severity_max = max((f.severity for f in all_findings), default=0.0)
    summary = (
        f"Analyzed {len(nodes)} nodes, {len(edges)} edges. "
        f"Found {len(all_findings)} suspicious subgraph(s) "
        f"({cluster_count} full anti-forensic cluster(s)). "
        f"Max severity: {severity_max:.2f}."
    )

    return GraphResponse(
        total_nodes=len(nodes),
        total_edges=len(edges),
        suspicious_subgraphs=all_findings,
        anti_forensic_clusters=cluster_count,
        summary=summary,
    )
