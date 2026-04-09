"""
ARM Provenance (arm_provenance)

Single-agent causal provenance tracking and graph-backed enforcement for ARM.

Core components:
- ProvenanceGraph: causal DAG tracking data flow, tool calls, and denials
- GraphProvenanceLayer: deterministic L2 replacement using graph traversal
- GraphAwareEngine: composes LayeredPolicyEngine + ProvenanceGraph

Data model:
- Trust hierarchy: 5-level total order for information flow control
- Security queries: taint analysis, reachability, counterfactual chain detection
- Field-level tracking: per-field trust on structured tool results

This module is agent-count-agnostic and designed for extensibility.
"""

from arm_provenance.provenance_graph import (
    ProvenanceGraph,
    NodeType,
    EdgeType,
    TrustLevel,
    ProvenanceNode,
    ProvenanceEdge,
    TaintQuery,
)
from arm_provenance.graph_provenance_layer import GraphProvenanceLayer
from arm_provenance.graph_aware_engine import GraphAwareEngine

__all__ = [
    "ProvenanceGraph",
    "NodeType",
    "EdgeType",
    "TrustLevel",
    "ProvenanceNode",
    "ProvenanceEdge",
    "TaintQuery",
    "GraphProvenanceLayer",
    "GraphAwareEngine",
]
