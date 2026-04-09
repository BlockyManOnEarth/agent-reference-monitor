"""
GraphProvenanceLayer -- deterministic graph-based provenance check (replaces L2).

Instead of asking the LLM to cite sources (which can be fabricated),
this layer queries the ProvenanceGraph directly:

  "For each argument of this tool call, what is the minimum trust level
   of its ancestor nodes in the causal DAG?"

If any argument traces back to an untrusted source below the required
threshold, DENY. No LLM round-trip, no citation fabrication risk.

This is what makes Theorem 1 (Mediated Integrity) real in code:
the proof's Step 3 says "L2 checks provenance" -- this layer does
exactly that via graph traversal, not string matching.
"""

from __future__ import annotations

from typing import Any

from arm_core.layers.base import EvaluationContext, LayerResult, LayerVerdict, PolicyLayer
from arm_provenance.provenance_graph import ProvenanceGraph, TrustLevel


class GraphProvenanceLayer(PolicyLayer):
    """
    Layer 2G: Graph-based Provenance Check.

    Deterministic replacement for the citation-based ProvenanceLayer.
    Consults the ProvenanceGraph to verify that every argument of a
    tool call traces back to a sufficiently trusted source.

    Also checks for counterfactual chains (causality laundering).
    """

    def __init__(
        self,
        graph: ProvenanceGraph,
        min_required_trust: TrustLevel = TrustLevel.USER_INPUT,
    ) -> None:
        self._graph = graph
        self._min_required_trust = min_required_trust

    @property
    def name(self) -> str:
        return "graph_provenance"

    @property
    def order(self) -> int:
        return 200  # Same slot as L2 -- replaces citation-based provenance

    def evaluate(
        self, tool_name: str, args: dict[str, Any], context: EvaluationContext
    ) -> LayerResult:
        # The call_id must be set in context metadata by GraphAwareEngine
        call_id = getattr(context, "_current_call_id", None)
        if call_id is None:
            # No graph context available -- fall through to other layers
            return LayerResult(
                verdict=LayerVerdict.PASS,
                layer_name=self.name,
                reason="No graph context -- deferring to other layers",
                tool_name=tool_name,
                args=args,
            )

        call_nid = f"call:{call_id}"
        if not self._graph.has_node(call_nid):
            return LayerResult(
                verdict=LayerVerdict.PASS,
                layer_name=self.name,
                reason="Tool call not yet in graph -- deferring",
                tool_name=tool_name,
                args=args,
            )

        # Check 1: taint from untrusted sources
        min_trust = self._graph.min_trust_to(call_nid)
        if min_trust is not None and min_trust < self._min_required_trust:
            sources = self._graph.taint_sources(
                call_nid, max_trust=TrustLevel(self._min_required_trust - 1)
            )
            return LayerResult(
                verdict=LayerVerdict.DENY,
                layer_name=self.name,
                reason=(
                    f"Graph provenance check FAILED: min trust is {min_trust.name} "
                    f"(required: {self._min_required_trust.name}). "
                    f"Taint sources: {sources[:5]}"
                ),
                tool_name=tool_name,
                args=args,
            )

        # Check 2: counterfactual chains (causality laundering)
        cf_chains = self._graph.counterfactual_chains(call_nid)
        if cf_chains:
            return LayerResult(
                verdict=LayerVerdict.DENY,
                layer_name=self.name,
                reason=(
                    f"Causality laundering detected: {len(cf_chains)} counterfactual "
                    f"chain(s) reach this tool call. First chain: {cf_chains[0]}"
                ),
                tool_name=tool_name,
                args=args,
            )

        return LayerResult(
            verdict=LayerVerdict.PASS,
            layer_name=self.name,
            reason="Graph provenance clean -- all ancestors meet trust threshold",
            tool_name=tool_name,
            args=args,
        )
