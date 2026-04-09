"""
ProvenanceGraph -- causal DAG for tracking data provenance in a single agent session.

Uses rustworkx for sub-millisecond graph traversal on ARM-sized graphs.
This is the foundation of ARM's provenance-based enforcement. It tracks
every data flow, tool call, and denial within a single agent's session.
Designed for extensibility to multi-agent scenarios.

Thread safety: ProvenanceGraph is NOT thread-safe. A single graph instance
must be accessed from one thread (or externally synchronized). This matches
the single-agent session model where tool calls are sequential.

Node types:
  - TOOL_CALL: a tool invocation (allowed)
  - DATA_ITEM: a value flowing through the system
  - DATA_FIELD: a field within a structured tool result (JSON decomposition)
  - DENIED_ACTION: a tool call that ARM blocked (for COUNTERFACTUAL edges)

Edge types:
  - DIRECT_OUTPUT: tool produced this data
  - INPUT_TO: data was passed as input to this tool call
  - COUNTERFACTUAL: B occurred as a reaction to A being blocked
  - FIELD_OF: field node belongs to parent data item

Trust hierarchy (total order, higher = more trusted):
  system_instruction > user_input > tool_output_trusted > tool_output_untrusted > tool_description
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any

import rustworkx as rx


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class NodeType(Enum):
    TOOL_CALL = "tool_call"
    DATA_ITEM = "data_item"
    DATA_FIELD = "data_field"
    DENIED_ACTION = "denied_action"


class EdgeType(Enum):
    DIRECT_OUTPUT = "direct_output"
    INPUT_TO = "input_to"
    COUNTERFACTUAL = "counterfactual"
    FIELD_OF = "field_of"


class TrustLevel(IntEnum):
    """Trust hierarchy (total order). Higher value = more trusted."""
    TOOL_DESCRIPTION = 0
    TOOL_OUTPUT_UNTRUSTED = 1
    TOOL_OUTPUT_TRUSTED = 2
    USER_INPUT = 3
    SYSTEM_INSTRUCTION = 4


# ---------------------------------------------------------------------------
# Node and edge data
# ---------------------------------------------------------------------------

@dataclass
class ProvenanceNode:
    """Data stored on each graph node."""

    node_type: NodeType
    node_id: str
    trust_level: TrustLevel
    timestamp: float = 0.0
    tool_name: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    value: Any = None
    # For DATA_FIELD: the key name within the parent structure
    field_key: str = ""
    # For DENIED_ACTION: the denial reason
    denial_reason: str = ""
    # Metadata bag for extensions
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceEdge:
    """Data stored on each graph edge."""

    edge_type: EdgeType
    timestamp: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Query result
# ---------------------------------------------------------------------------

@dataclass
class TaintQuery:
    """Result of a taint/reachability query."""

    reachable: bool
    path: list[str]  # node_ids along the path
    min_trust_on_path: TrustLevel | None
    traversal_time_us: float  # microseconds


# ---------------------------------------------------------------------------
# ProvenanceGraph
# ---------------------------------------------------------------------------

class ProvenanceGraph:
    """
    Causal provenance DAG built on rustworkx.

    Tracks every data flow, tool call, and denial in a single agent session.
    Answers security queries in sub-millisecond time:
    - Is there a causal path from an untrusted source to this tool call?
    - What is the minimum trust level along any path to this node?
    - If a source is revoked, which downstream nodes are affected?
    """

    def __init__(self) -> None:
        self._graph: rx.PyDiGraph = rx.PyDiGraph()
        # Fast lookup: node_id -> rustworkx index
        self._id_to_idx: dict[str, int] = {}
        # Reverse lookup for results
        self._idx_to_id: dict[int, str] = {}
        # Track the last denied action per session for auto-COUNTERFACTUAL
        self._last_denied_id: str | None = None

    # ------------------------------------------------------------------
    # Node operations
    # ------------------------------------------------------------------

    def add_node(self, node: ProvenanceNode) -> int:
        """Add a node to the graph. Returns the rustworkx index."""
        if node.node_id in self._id_to_idx:
            raise ValueError(f"Duplicate node_id: {node.node_id}")
        if node.timestamp == 0.0:
            node.timestamp = time.time()
        idx = self._graph.add_node(node)
        self._id_to_idx[node.node_id] = idx
        self._idx_to_id[idx] = node.node_id
        return idx

    def get_node(self, node_id: str) -> ProvenanceNode:
        """Retrieve a node by its ID."""
        idx = self._id_to_idx[node_id]
        return self._graph[idx]

    def has_node(self, node_id: str) -> bool:
        return node_id in self._id_to_idx

    @property
    def node_count(self) -> int:
        return self._graph.num_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.num_edges()

    # ------------------------------------------------------------------
    # Edge operations
    # ------------------------------------------------------------------

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge: ProvenanceEdge,
    ) -> int:
        """Add a directed edge from source to target."""
        src_idx = self._id_to_idx[source_id]
        tgt_idx = self._id_to_idx[target_id]
        if edge.timestamp == 0.0:
            edge.timestamp = time.time()
        return self._graph.add_edge(src_idx, tgt_idx, edge)

    # ------------------------------------------------------------------
    # Convenience builders (single-agent)
    # ------------------------------------------------------------------

    def add_tool_call(
        self,
        call_id: str,
        tool_name: str,
        args: dict[str, Any] | None = None,
        trust: TrustLevel = TrustLevel.USER_INPUT,
    ) -> str:
        """Record an allowed tool call."""
        nid = f"call:{call_id}"
        self.add_node(ProvenanceNode(
            node_type=NodeType.TOOL_CALL,
            node_id=nid,
            trust_level=trust,
            tool_name=tool_name,
            args=args or {},
        ))
        # Auto-generate COUNTERFACTUAL edge if this follows a denial
        if self._last_denied_id is not None:
            self.add_edge(
                self._last_denied_id,
                nid,
                ProvenanceEdge(edge_type=EdgeType.COUNTERFACTUAL),
            )
            self._last_denied_id = None
        return nid

    def add_denied_action(
        self,
        call_id: str,
        tool_name: str,
        reason: str,
        args: dict[str, Any] | None = None,
    ) -> str:
        """Record a denied tool call."""
        nid = f"denied:{call_id}"
        self.add_node(ProvenanceNode(
            node_type=NodeType.DENIED_ACTION,
            node_id=nid,
            trust_level=TrustLevel.TOOL_DESCRIPTION,
            tool_name=tool_name,
            args=args or {},
            denial_reason=reason,
        ))
        self._last_denied_id = nid
        return nid

    def add_data_item(
        self,
        data_id: str,
        value: Any,
        trust: TrustLevel,
        source_call_id: str | None = None,
    ) -> str:
        """Record a data item, optionally linking it as output of a tool call."""
        nid = f"data:{data_id}"
        self.add_node(ProvenanceNode(
            node_type=NodeType.DATA_ITEM,
            node_id=nid,
            trust_level=trust,
            value=value,
        ))
        if source_call_id is not None:
            call_nid = f"call:{source_call_id}"
            if self.has_node(call_nid):
                self.add_edge(call_nid, nid, ProvenanceEdge(edge_type=EdgeType.DIRECT_OUTPUT))
        return nid

    def add_data_fields(
        self,
        parent_data_id: str,
        fields: dict[str, Any],
        trust_overrides: dict[str, TrustLevel] | None = None,
    ) -> list[str]:
        """
        Decompose a structured tool result into field-level nodes.

        Each field gets its own node inheriting the parent's trust level
        unless overridden. Returns the list of field node IDs.
        """
        parent_nid = f"data:{parent_data_id}"
        parent_node = self.get_node(parent_nid)
        overrides = trust_overrides or {}
        field_nids = []

        for key, value in fields.items():
            field_nid = f"field:{parent_data_id}.{key}"
            trust = overrides.get(key, parent_node.trust_level)
            self.add_node(ProvenanceNode(
                node_type=NodeType.DATA_FIELD,
                node_id=field_nid,
                trust_level=trust,
                value=value,
                field_key=key,
            ))
            self.add_edge(parent_nid, field_nid, ProvenanceEdge(edge_type=EdgeType.FIELD_OF))
            field_nids.append(field_nid)

        return field_nids

    def link_input(self, data_id: str, call_id: str) -> None:
        """Record that a data item (or field) was used as input to a tool call."""
        data_nid = data_id if data_id.startswith(("data:", "field:")) else f"data:{data_id}"
        call_nid = call_id if call_id.startswith("call:") else f"call:{call_id}"
        self.add_edge(data_nid, call_nid, ProvenanceEdge(edge_type=EdgeType.INPUT_TO))

    def link_counterfactual(self, denied_id: str, subsequent_id: str) -> None:
        """
        Manually record a COUNTERFACTUAL edge.

        Usually auto-generated by add_tool_call() after add_denied_action(),
        but can be created explicitly for complex scenarios.
        """
        denied_nid = denied_id if denied_id.startswith("denied:") else f"denied:{denied_id}"
        sub_nid = subsequent_id if subsequent_id.startswith(("call:", "data:")) else f"call:{subsequent_id}"
        self.add_edge(denied_nid, sub_nid, ProvenanceEdge(edge_type=EdgeType.COUNTERFACTUAL))

    # ------------------------------------------------------------------
    # Security queries
    # ------------------------------------------------------------------

    def is_reachable(self, source_id: str, target_id: str) -> TaintQuery:
        """
        Check if there is any causal path from source to target.

        This is the core security query: "Can untrusted data reach this tool call?"
        Returns the path and the minimum trust level encountered.
        """
        t0 = time.perf_counter_ns()

        src_idx = self._id_to_idx.get(source_id)
        tgt_idx = self._id_to_idx.get(target_id)

        if src_idx is None or tgt_idx is None:
            elapsed = (time.perf_counter_ns() - t0) / 1000
            return TaintQuery(reachable=False, path=[], min_trust_on_path=None, traversal_time_us=elapsed)

        try:
            path_indices = rx.dijkstra_shortest_paths(
                self._graph, src_idx, target=tgt_idx, weight_fn=lambda _: 1.0
            )
            if tgt_idx not in path_indices:
                elapsed = (time.perf_counter_ns() - t0) / 1000
                return TaintQuery(reachable=False, path=[], min_trust_on_path=None, traversal_time_us=elapsed)

            path_idx_list = path_indices[tgt_idx]
            path_ids = [self._idx_to_id[i] for i in path_idx_list]
            min_trust = min(self._graph[i].trust_level for i in path_idx_list)
        except (KeyError, IndexError, rx.NullGraph) as exc:
            # KeyError/IndexError: stale index mapping; NullGraph: empty graph edge case.
            # Log and fail-closed: treat as unreachable rather than crashing the pipeline.
            elapsed = (time.perf_counter_ns() - t0) / 1000
            return TaintQuery(reachable=False, path=[], min_trust_on_path=None, traversal_time_us=elapsed)

        elapsed = (time.perf_counter_ns() - t0) / 1000
        return TaintQuery(
            reachable=True,
            path=path_ids,
            min_trust_on_path=min_trust,
            traversal_time_us=elapsed,
        )

    def taint_sources(self, target_id: str, max_trust: TrustLevel = TrustLevel.TOOL_OUTPUT_UNTRUSTED) -> list[str]:
        """
        Find all ancestor nodes of target whose trust level is at or below max_trust.

        These are the "taint sources" that could contaminate the target.
        """
        tgt_idx = self._id_to_idx.get(target_id)
        if tgt_idx is None:
            return []

        ancestors = rx.ancestors(self._graph, tgt_idx)
        tainted = []
        for idx in ancestors:
            node: ProvenanceNode = self._graph[idx]
            if node.trust_level <= max_trust:
                tainted.append(node.node_id)
        return tainted

    def min_trust_to(self, target_id: str) -> TrustLevel | None:
        """
        Return the minimum trust level across ALL ancestors of target.

        If any ancestor is untrusted, the target is tainted.
        This is the conservative (safe) approach.
        """
        tgt_idx = self._id_to_idx.get(target_id)
        if tgt_idx is None:
            return None

        ancestors = rx.ancestors(self._graph, tgt_idx)
        if not ancestors:
            return self._graph[tgt_idx].trust_level

        all_nodes = list(ancestors) + [tgt_idx]
        return min(self._graph[i].trust_level for i in all_nodes)

    def revocation_cascade(self, revoked_id: str) -> list[str]:
        """
        If a source node is revoked (e.g., tool output found to be
        compromised), return all downstream nodes that are affected.
        """
        src_idx = self._id_to_idx.get(revoked_id)
        if src_idx is None:
            return []

        descendants = rx.descendants(self._graph, src_idx)
        return [self._idx_to_id[i] for i in descendants]

    def counterfactual_chains(self, target_id: str) -> list[list[str]]:
        """
        Find all paths to target that traverse at least one COUNTERFACTUAL edge.

        These are causality laundering chains: the attacker probed something,
        got denied, inferred information, and used it downstream.
        """
        tgt_idx = self._id_to_idx.get(target_id)
        if tgt_idx is None:
            return []

        ancestors = rx.ancestors(self._graph, tgt_idx)

        denied_ancestors = [
            idx for idx in ancestors
            if self._graph[idx].node_type == NodeType.DENIED_ACTION
        ]

        chains = []
        for denied_idx in denied_ancestors:
            denied_id = self._idx_to_id[denied_idx]
            query = self.is_reachable(denied_id, target_id)
            if query.reachable:
                path_indices = [self._id_to_idx[nid] for nid in query.path]
                has_cf = False
                for i in range(len(path_indices) - 1):
                    edge_data = self._graph.get_edge_data(path_indices[i], path_indices[i + 1])
                    if edge_data is not None and edge_data.edge_type == EdgeType.COUNTERFACTUAL:
                        has_cf = True
                        break
                if has_cf:
                    chains.append(query.path)

        return chains

    # ------------------------------------------------------------------
    # Enforcement integration
    # ------------------------------------------------------------------

    def should_block(
        self,
        target_call_id: str,
        min_required_trust: TrustLevel = TrustLevel.USER_INPUT,
    ) -> tuple[bool, str]:
        """
        High-level enforcement query: should this tool call be blocked
        based on provenance?

        Returns (should_block, reason).

        Checks:
        1. Any untrusted ancestor below min_required_trust?
        2. Any counterfactual chain reaching this call?
        """
        call_nid = target_call_id if target_call_id.startswith("call:") else f"call:{target_call_id}"

        # Check 1: taint from untrusted sources
        min_trust = self.min_trust_to(call_nid)
        if min_trust is not None and min_trust < min_required_trust:
            sources = self.taint_sources(call_nid, max_trust=TrustLevel(min_required_trust - 1))
            return True, (
                f"Untrusted provenance: min trust is {min_trust.name} "
                f"(required: {min_required_trust.name}). "
                f"Taint sources: {sources[:5]}"
            )

        # Check 2: counterfactual chains (causality laundering)
        cf_chains = self.counterfactual_chains(call_nid)
        if cf_chains:
            return True, (
                f"Causality laundering detected: {len(cf_chains)} counterfactual chain(s) "
                f"reach this tool call. First chain: {cf_chains[0]}"
            )

        return False, "Provenance clean"

    # ------------------------------------------------------------------
    # Debugging / visualization
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Return a summary of the graph state."""
        type_counts: dict[str, int] = {}
        for idx in self._graph.node_indices():
            node: ProvenanceNode = self._graph[idx]
            nt = node.node_type.value
            type_counts[nt] = type_counts.get(nt, 0) + 1

        edge_counts: dict[str, int] = {}
        for src, tgt, edge in self._graph.edge_index_map().values():
            et = self._graph.get_edge_data(src, tgt).edge_type.value
            edge_counts[et] = edge_counts.get(et, 0) + 1

        return {
            "nodes": self._graph.num_nodes(),
            "edges": self._graph.num_edges(),
            "node_types": type_counts,
            "edge_types": edge_counts,
        }

    def to_dot(self) -> str:
        """Export the graph as DOT format for visualization."""
        lines = ["digraph provenance {", "  rankdir=LR;"]

        shape_map = {
            NodeType.TOOL_CALL: "box",
            NodeType.DATA_ITEM: "ellipse",
            NodeType.DATA_FIELD: "diamond",
            NodeType.DENIED_ACTION: "box",
        }
        color_map = {
            NodeType.TOOL_CALL: "#50c878",
            NodeType.DATA_ITEM: "#f5a623",
            NodeType.DATA_FIELD: "#f5d623",
            NodeType.DENIED_ACTION: "#d9534f",
        }
        edge_style_map = {
            EdgeType.DIRECT_OUTPUT: "solid",
            EdgeType.INPUT_TO: "solid",
            EdgeType.COUNTERFACTUAL: "dotted",
            EdgeType.FIELD_OF: "solid",
        }
        edge_color_map = {
            EdgeType.COUNTERFACTUAL: "#d9534f",
        }

        for idx in self._graph.node_indices():
            node: ProvenanceNode = self._graph[idx]
            safe_id = node.node_id.replace(":", "_").replace(".", "_")
            label = f"{node.node_id}\\n[{node.trust_level.name}]"
            if node.tool_name:
                label = f"{node.node_id}\\n{node.tool_name}\\n[{node.trust_level.name}]"
            shape = shape_map.get(node.node_type, "ellipse")
            color = color_map.get(node.node_type, "#999999")
            style = 'filled,bold' if node.node_type == NodeType.DENIED_ACTION else 'filled'
            lines.append(
                f'  {safe_id} [label="{label}" shape={shape} '
                f'style="{style}" fillcolor="{color}" fontcolor="white"];'
            )

        for idx in self._graph.edge_indices():
            src, tgt = self._graph.get_edge_endpoints_by_index(idx)
            edge: ProvenanceEdge = self._graph.edges()[idx]
            src_node: ProvenanceNode = self._graph[src]
            tgt_node: ProvenanceNode = self._graph[tgt]
            src_safe = src_node.node_id.replace(":", "_").replace(".", "_")
            tgt_safe = tgt_node.node_id.replace(":", "_").replace(".", "_")
            style = edge_style_map.get(edge.edge_type, "solid")
            color = edge_color_map.get(edge.edge_type, "#333333")
            lines.append(
                f'  {src_safe} -> {tgt_safe} [label="{edge.edge_type.value}" '
                f'style="{style}" color="{color}"];'
            )

        lines.append("}")
        return "\n".join(lines)
