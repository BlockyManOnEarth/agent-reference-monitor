"""
GraphAwareEngine -- wraps LayeredPolicyEngine + ProvenanceGraph.

This is the Phase 1.5 deliverable that makes the formal appendix's
Theorem 1 (Mediated Integrity) real in code. It:

1. Records every tool call and its data inputs in the ProvenanceGraph
2. Replaces L2 (citation-based) with GraphProvenanceLayer (graph traversal)
3. Auto-generates COUNTERFACTUAL edges on deny-then-retry sequences
4. Records tool results as data nodes after ALLOW decisions
5. Decomposes structured results into field-level nodes

arm_core is NOT modified. This engine composes arm_core's LayeredPolicyEngine
with arm_provenance's graph, keeping the separation clean.
"""

from __future__ import annotations

import uuid
from typing import Any

from arm_core.capability_token import CapabilityToken
from arm_core.layers.base import EvaluationContext
from arm_core.layers.hard_boundaries import HardBoundariesLayer
from arm_core.layers.schema_derived import SchemaDerivedLayer
from arm_core.layers.manual_policy import ManualPolicyLayer
from arm_core.policy_engine import Decision, LayeredPolicyEngine, PolicyDecision

from arm_provenance.provenance_graph import (
    ProvenanceGraph,
    ProvenanceEdge,
    EdgeType,
    TrustLevel,
)
from arm_provenance.graph_provenance_layer import GraphProvenanceLayer
from arm_provenance.privileged_action_layer import (
    DEFAULT_PRIVILEGED_ACTION_TOOLS,
    PrivilegedActionLayer,
)


class GraphAwareEngine:
    """
    Composes LayeredPolicyEngine + ProvenanceGraph for graph-backed enforcement.

    On every tool call:
    - Pre-evaluate: record the tool call node in the graph, link input data edges
    - Evaluate: run L1 + L2G (graph provenance) + L3 + L5 pipeline
    - Post-evaluate:
      - On ALLOW: record tool result as data node
      - On DENY: record denied action, set up COUNTERFACTUAL tracking
    """

    def __init__(
        self,
        token: CapabilityToken | None = None,
        graph: ProvenanceGraph | None = None,
        min_required_trust: TrustLevel = TrustLevel.TOOL_OUTPUT_TRUSTED,
        privileged_tools: frozenset[str] | None = None,
    ) -> None:
        self.graph = graph or ProvenanceGraph()
        self._min_required_trust = min_required_trust

        # Build the layer pipeline: L1 + L2G (graph) + L2.5 (privileged action) + L3 + L5
        self._graph_layer = GraphProvenanceLayer(
            graph=self.graph,
            min_required_trust=min_required_trust,
        )
        self._privileged_action_layer = PrivilegedActionLayer(
            graph=self.graph,
            privileged_tools=privileged_tools,
        )
        self._engine = LayeredPolicyEngine(
            layers=[
                HardBoundariesLayer(),
                self._graph_layer,
                self._privileged_action_layer,
                SchemaDerivedLayer(),
                ManualPolicyLayer(),
            ],
            token=token,
        )
        self._context: EvaluationContext | None = None
        self._call_counter = 0

    def set_context(self, context: EvaluationContext) -> None:
        """Set the session context for the engine."""
        self._context = context
        self._engine.set_context(context)

    def evaluate(
        self,
        tool_name: str,
        args: dict[str, Any],
        input_data_ids: list[str] | None = None,
    ) -> PolicyDecision:
        """
        Evaluate a tool call with full graph integration.

        Args:
            tool_name: Name of the tool being called.
            args: Arguments to the tool call.
            input_data_ids: IDs of data nodes (from prior tool results) that
                feed into this call's arguments. These create INPUT_TO edges
                in the graph. Use "data:xxx" or "field:xxx.key" format.

        Returns:
            PolicyDecision with ALLOW or DENY.
        """
        self._call_counter += 1
        call_id = f"{tool_name}_{self._call_counter}_{uuid.uuid4().hex[:6]}"

        # Pre-evaluate: record the tool call in the graph
        call_nid = self.graph.add_tool_call(
            call_id=call_id,
            tool_name=tool_name,
            args=args,
        )

        # Link input data edges
        if input_data_ids:
            for data_id in input_data_ids:
                if self.graph.has_node(data_id):
                    self.graph.link_input(data_id, call_nid)

        # Inject the call_id into the context so GraphProvenanceLayer can find it
        if self._context is not None:
            self._context._current_call_id = call_id  # type: ignore[attr-defined]
        else:
            ctx = EvaluationContext(session_id="default", agent_id="default")
            ctx._current_call_id = call_id  # type: ignore[attr-defined]
            self._engine.set_context(ctx)

        # Evaluate through the layer pipeline
        decision = self._engine.evaluate(tool_name, args)

        # Post-evaluate: record outcome
        if decision.denied:
            self.graph.add_denied_action(
                call_id=f"{call_id}_denied",
                tool_name=tool_name,
                reason=decision.reason,
                args=args,
            )

        return decision

    def record_tool_result(
        self,
        call_id_prefix: str,
        result: Any,
        trust: TrustLevel = TrustLevel.TOOL_OUTPUT_TRUSTED,
        fields: dict[str, Any] | None = None,
        field_trust_overrides: dict[str, TrustLevel] | None = None,
    ) -> str:
        """
        Record a tool's result as a data node after an ALLOW decision.

        Call this after evaluate() returns ALLOW and the tool executes.

        Args:
            call_id_prefix: The tool_name used in evaluate(). Used to find
                the corresponding call node.
            result: The raw tool result value.
            trust: Trust level for the result (default: TOOL_OUTPUT_TRUSTED).
            fields: If the result is structured (dict/JSON), decompose into
                field-level nodes for per-field trust tracking.
            field_trust_overrides: Per-field trust overrides (e.g., {"email": TOOL_OUTPUT_UNTRUSTED}).

        Returns:
            The data node ID (e.g., "data:result_xxx").
        """
        data_id = f"result_{call_id_prefix}_{uuid.uuid4().hex[:6]}"

        # Find the most recent call node matching this prefix
        source_call_id = None
        for nid in reversed(list(self.graph._id_to_idx.keys())):
            if nid.startswith(f"call:{call_id_prefix}"):
                source_call_id = nid.replace("call:", "")
                break

        data_nid = self.graph.add_data_item(
            data_id=data_id,
            value=result,
            trust=trust,
            source_call_id=source_call_id,
        )

        # Field-level decomposition
        if fields is not None:
            self.graph.add_data_fields(
                parent_data_id=data_id,
                fields=fields,
                trust_overrides=field_trust_overrides,
            )

        return data_nid

    def record_user_input(
        self,
        input_id: str,
        value: Any,
    ) -> str:
        """Record a user input as a trusted data node in the graph."""
        return self.graph.add_data_item(
            data_id=input_id,
            value=value,
            trust=TrustLevel.USER_INPUT,
        )

    @classmethod
    def default(
        cls,
        token: CapabilityToken | None = None,
        min_required_trust: TrustLevel = TrustLevel.TOOL_OUTPUT_TRUSTED,
        privileged_tools: frozenset[str] | None = None,
    ) -> GraphAwareEngine:
        """Convenience constructor with default settings."""
        return cls(
            token=token,
            min_required_trust=min_required_trust,
            privileged_tools=privileged_tools,
        )
