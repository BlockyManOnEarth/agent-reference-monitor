"""
PrivilegedActionLayer: blocks side-effecting tools when untrusted data is in the session.

This layer addresses the "provenance gap" where LLM-mediated semantic flows
(prompt injection) cannot be caught by syntactic provenance tracing alone.
When the LLM reads injected instructions from a tool output and composes a
NEW tool call with fresh arguments, there is no syntactic link for L2G to
trace. The connection is semantic (inside the LLM's reasoning), not observable
in the data flow.

Strategy (Approach 2: Privileged-Action Policy):
  Define two tool classes:
    - Readers: tools that ingest external data (already classified as UNTRUSTED_DATA_TOOLS)
    - Actors: tools that perform irreversible side effects (PRIVILEGED_ACTION_TOOLS)

  When the provenance graph contains ANY untrusted data node, block all
  privileged action tools. This is ARM's deterministic equivalent of FIDES's
  P-T (privilege-taint) policy, but expressed as a graph-native constraint
  rather than a label-propagation rule.

Layer order: 250 (between L2G at 200 and L3 at 300). This means:
  - L1 (hard boundaries) catches absolute violations first
  - L2G (graph provenance) catches syntactic data flows
  - L2.5 (this layer) catches semantic flows via privilege restriction
  - L3/L5 handle schema and manual policies
"""

from __future__ import annotations

from typing import Any

from arm_core.layers.base import EvaluationContext, LayerResult, LayerVerdict, PolicyLayer
from arm_provenance.provenance_graph import NodeType, ProvenanceGraph, TrustLevel


# Default set of tools that perform irreversible side effects.
# These are blocked when untrusted data is present in the session.
# Deployments can override this set via the constructor.
DEFAULT_PRIVILEGED_ACTION_TOOLS: frozenset[str] = frozenset({
    # workspace suite
    "send_email", "delete_email", "forward_email",
    "invite_user_to_slack", "remove_user_from_slack",
    "create_calendar_event", "delete_calendar_event",
    "append_to_file", "create_file", "delete_file",
    # slack suite
    "send_direct_message", "send_channel_message",
    "add_user_to_channel", "remove_user_from_channel",
    # travel suite
    "reserve_hotel", "reserve_restaurant", "book_car",
    "make_transaction", "update_password", "send_verification_code",
    "purchase_flight_ticket",
    # banking suite
    "send_money", "schedule_transaction", "set_standing_order",
    "update_password",
})


class PrivilegedActionLayer(PolicyLayer):
    """
    Layer 2.5: Privileged-Action Policy.

    Blocks side-effecting (privileged) tool calls when the provenance graph
    contains untrusted data nodes. This catches LLM-mediated semantic flows
    that L2G's syntactic provenance tracing cannot detect.

    The layer checks two conditions:
      1. Is the current tool in the privileged action set?
      2. Does the provenance graph contain any TOOL_OUTPUT_UNTRUSTED data nodes?

    If both are true, the tool call is denied. Non-privileged tools (reads,
    lookups) are always allowed through this layer, even after untrusted data
    enters the session. This keeps false positives low: the agent can still
    read and summarize, but cannot send emails or delete files.
    """

    def __init__(
        self,
        graph: ProvenanceGraph,
        privileged_tools: frozenset[str] | None = None,
    ) -> None:
        self._graph = graph
        self._privileged_tools = privileged_tools or DEFAULT_PRIVILEGED_ACTION_TOOLS

    @property
    def name(self) -> str:
        return "privileged_action"

    @property
    def order(self) -> int:
        return 250  # Between L2G (200) and L3 (300)

    def _session_has_untrusted_data(self) -> list[str]:
        """Check if the provenance graph contains any untrusted data nodes.

        Returns a list of untrusted data node IDs (empty if none found).
        """
        untrusted_nodes = []
        for node_id, idx in self._graph._id_to_idx.items():
            node = self._graph._graph[idx]
            if (
                node.node_type in (NodeType.DATA_ITEM, NodeType.DATA_FIELD)
                and node.trust_level <= TrustLevel.TOOL_OUTPUT_UNTRUSTED
            ):
                untrusted_nodes.append(node_id)
        return untrusted_nodes

    def evaluate(
        self, tool_name: str, args: dict[str, Any], context: EvaluationContext
    ) -> LayerResult:
        # Only check privileged tools
        if tool_name not in self._privileged_tools:
            return LayerResult(
                verdict=LayerVerdict.PASS,
                layer_name=self.name,
                reason=f"'{tool_name}' is not a privileged action; no restriction",
                tool_name=tool_name,
                args=args,
            )

        # Check if untrusted data exists in the session
        untrusted_nodes = self._session_has_untrusted_data()
        if not untrusted_nodes:
            return LayerResult(
                verdict=LayerVerdict.PASS,
                layer_name=self.name,
                reason="No untrusted data in session; privileged action allowed",
                tool_name=tool_name,
                args=args,
            )

        # Privileged tool + untrusted data in session = DENY
        return LayerResult(
            verdict=LayerVerdict.DENY,
            layer_name=self.name,
            reason=(
                f"Privileged action '{tool_name}' blocked: session contains "
                f"untrusted data from {len(untrusted_nodes)} source(s). "
                f"First untrusted node: {untrusted_nodes[0]}. "
                f"This prevents LLM-mediated prompt injection where the model "
                f"interprets injected instructions and composes new tool calls."
            ),
            tool_name=tool_name,
            args=args,
        )
