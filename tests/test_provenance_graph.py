"""
Tests for ProvenanceGraph -- the causal DAG for agent data provenance.

Covers:
  - [02] Provenance in Databases: graph construction, why/how/where provenance queries
  - [03] IFC / Taint: trust hierarchy, conservative taint propagation (min_trust_to)
  - [05] Counterfactual Causality: COUNTERFACTUAL edges, auto-generation, chain detection
  - [06] Causality Laundering: should_block() combining taint + counterfactual checks

Run: uv run pytest tests/test_provenance_graph.py -v
"""

import pytest

from arm_provenance.provenance_graph import (
    ProvenanceGraph,
    ProvenanceNode,
    ProvenanceEdge,
    NodeType,
    EdgeType,
    TrustLevel,
)


# ============================================================================
# [02] Provenance in Databases: Graph Construction
# ============================================================================

class TestGraphConstruction:
    """Basic graph operations: add nodes, edges, lookup."""

    def test_add_node(self):
        g = ProvenanceGraph()
        idx = g.add_node(ProvenanceNode(
            node_type=NodeType.DATA_ITEM,
            node_id="data:test",
            trust_level=TrustLevel.USER_INPUT,
        ))
        assert g.node_count == 1
        assert g.has_node("data:test")

    def test_duplicate_node_raises(self):
        g = ProvenanceGraph()
        g.add_node(ProvenanceNode(
            node_type=NodeType.DATA_ITEM,
            node_id="data:dup",
            trust_level=TrustLevel.USER_INPUT,
        ))
        with pytest.raises(ValueError, match="Duplicate node_id"):
            g.add_node(ProvenanceNode(
                node_type=NodeType.DATA_ITEM,
                node_id="data:dup",
                trust_level=TrustLevel.USER_INPUT,
            ))

    def test_add_edge(self):
        g = ProvenanceGraph()
        g.add_node(ProvenanceNode(node_type=NodeType.TOOL_CALL, node_id="call:a", trust_level=TrustLevel.USER_INPUT))
        g.add_node(ProvenanceNode(node_type=NodeType.DATA_ITEM, node_id="data:b", trust_level=TrustLevel.USER_INPUT))
        g.add_edge("call:a", "data:b", ProvenanceEdge(edge_type=EdgeType.DIRECT_OUTPUT))
        assert g.edge_count == 1

    def test_get_node(self):
        g = ProvenanceGraph()
        g.add_node(ProvenanceNode(
            node_type=NodeType.TOOL_CALL,
            node_id="call:x",
            trust_level=TrustLevel.SYSTEM_INSTRUCTION,
            tool_name="read_file",
        ))
        node = g.get_node("call:x")
        assert node.tool_name == "read_file"
        assert node.trust_level == TrustLevel.SYSTEM_INSTRUCTION


# ============================================================================
# [02] Provenance in Databases: Convenience Builders
# ============================================================================

class TestConvenienceBuilders:
    """add_tool_call, add_data_item, add_data_fields, link_input."""

    def test_add_tool_call(self):
        g = ProvenanceGraph()
        nid = g.add_tool_call("tc1", "read_emails", args={"inbox": "main"})
        assert nid == "call:tc1"
        node = g.get_node("call:tc1")
        assert node.node_type == NodeType.TOOL_CALL
        assert node.tool_name == "read_emails"

    def test_add_data_item_linked_to_call(self):
        g = ProvenanceGraph()
        g.add_tool_call("tc1", "read_emails")
        data_nid = g.add_data_item("result1", {"emails": []}, TrustLevel.TOOL_OUTPUT_TRUSTED, source_call_id="tc1")
        assert data_nid == "data:result1"
        assert g.edge_count == 1  # DIRECT_OUTPUT edge

    def test_add_data_fields_decomposition(self):
        g = ProvenanceGraph()
        g.add_tool_call("tc1", "read_emails")
        g.add_data_item("r1", {"name": "Alice", "email": "a@b.com"}, TrustLevel.TOOL_OUTPUT_TRUSTED, source_call_id="tc1")
        field_nids = g.add_data_fields(
            "r1",
            {"name": "Alice", "email": "a@b.com"},
            trust_overrides={"email": TrustLevel.TOOL_OUTPUT_UNTRUSTED},
        )
        assert len(field_nids) == 2
        assert g.has_node("field:r1.name")
        assert g.has_node("field:r1.email")
        # name inherits parent trust
        assert g.get_node("field:r1.name").trust_level == TrustLevel.TOOL_OUTPUT_TRUSTED
        # email overridden to untrusted
        assert g.get_node("field:r1.email").trust_level == TrustLevel.TOOL_OUTPUT_UNTRUSTED

    def test_link_input(self):
        g = ProvenanceGraph()
        g.add_tool_call("tc1", "read_emails")
        g.add_data_item("r1", "some data", TrustLevel.TOOL_OUTPUT_TRUSTED, source_call_id="tc1")
        g.add_tool_call("tc2", "send_email")
        g.link_input("data:r1", "call:tc2")
        # 3 edges: tc1->r1 (DIRECT_OUTPUT), r1->tc2 (INPUT_TO), plus no COUNTERFACTUAL
        assert g.edge_count == 2


# ============================================================================
# [03] IFC / Taint: Trust Hierarchy and Conservative Propagation
# ============================================================================

class TestTrustHierarchy:
    """Trust level ordering and taint propagation."""

    def test_trust_level_ordering(self):
        """Trust hierarchy is a total order: TOOL_DESCRIPTION < ... < SYSTEM_INSTRUCTION."""
        assert TrustLevel.TOOL_DESCRIPTION < TrustLevel.TOOL_OUTPUT_UNTRUSTED
        assert TrustLevel.TOOL_OUTPUT_UNTRUSTED < TrustLevel.TOOL_OUTPUT_TRUSTED
        assert TrustLevel.TOOL_OUTPUT_TRUSTED < TrustLevel.USER_INPUT
        assert TrustLevel.USER_INPUT < TrustLevel.SYSTEM_INSTRUCTION

    def test_min_trust_single_node(self):
        g = ProvenanceGraph()
        g.add_data_item("d1", "hello", TrustLevel.USER_INPUT)
        assert g.min_trust_to("data:d1") == TrustLevel.USER_INPUT

    def test_min_trust_chain_propagation(self):
        """Taint union: min trust across all ancestors."""
        g = ProvenanceGraph()
        # user input (trusted) -> tool call -> untrusted result -> tool call 2
        g.add_data_item("user_msg", "do something", TrustLevel.USER_INPUT)
        g.add_tool_call("tc1", "read_emails")
        g.link_input("data:user_msg", "call:tc1")
        g.add_data_item("r1", "email content", TrustLevel.TOOL_OUTPUT_UNTRUSTED, source_call_id="tc1")
        g.add_tool_call("tc2", "send_email")
        g.link_input("data:r1", "call:tc2")

        # min trust to tc2 should be TOOL_OUTPUT_UNTRUSTED (from r1)
        assert g.min_trust_to("call:tc2") == TrustLevel.TOOL_OUTPUT_UNTRUSTED

    def test_min_trust_multiple_inputs_takes_minimum(self):
        """When multiple inputs feed a call, min trust = minimum of all."""
        g = ProvenanceGraph()
        g.add_data_item("trusted", "safe", TrustLevel.USER_INPUT)
        g.add_data_item("untrusted", "unsafe", TrustLevel.TOOL_OUTPUT_UNTRUSTED)
        g.add_tool_call("tc1", "combine")
        g.link_input("data:trusted", "call:tc1")
        g.link_input("data:untrusted", "call:tc1")

        assert g.min_trust_to("call:tc1") == TrustLevel.TOOL_OUTPUT_UNTRUSTED

    def test_taint_sources(self):
        """Find all untrusted ancestors."""
        g = ProvenanceGraph()
        g.add_data_item("clean", "ok", TrustLevel.USER_INPUT)
        g.add_data_item("dirty", "bad", TrustLevel.TOOL_OUTPUT_UNTRUSTED)
        g.add_tool_call("tc1", "merge")
        g.link_input("data:clean", "call:tc1")
        g.link_input("data:dirty", "call:tc1")

        sources = g.taint_sources("call:tc1", max_trust=TrustLevel.TOOL_OUTPUT_UNTRUSTED)
        assert "data:dirty" in sources
        assert "data:clean" not in sources


# ============================================================================
# [02] Provenance in Databases: Reachability / How-Provenance
# ============================================================================

class TestReachability:
    """is_reachable() -- the core security query."""

    def test_direct_reachability(self):
        g = ProvenanceGraph()
        g.add_tool_call("tc1", "read")
        g.add_data_item("r1", "data", TrustLevel.TOOL_OUTPUT_TRUSTED, source_call_id="tc1")

        q = g.is_reachable("call:tc1", "data:r1")
        assert q.reachable is True
        assert len(q.path) >= 2

    def test_transitive_reachability(self):
        g = ProvenanceGraph()
        g.add_data_item("d1", "x", TrustLevel.TOOL_OUTPUT_UNTRUSTED)
        g.add_tool_call("tc1", "transform")
        g.link_input("data:d1", "call:tc1")
        g.add_data_item("d2", "y", TrustLevel.TOOL_OUTPUT_TRUSTED, source_call_id="tc1")
        g.add_tool_call("tc2", "send")
        g.link_input("data:d2", "call:tc2")

        q = g.is_reachable("data:d1", "call:tc2")
        assert q.reachable is True
        assert q.min_trust_on_path == TrustLevel.TOOL_OUTPUT_UNTRUSTED

    def test_no_reachability(self):
        g = ProvenanceGraph()
        g.add_data_item("d1", "x", TrustLevel.USER_INPUT)
        g.add_data_item("d2", "y", TrustLevel.USER_INPUT)
        # No edge between them
        q = g.is_reachable("data:d1", "data:d2")
        assert q.reachable is False

    def test_nonexistent_node(self):
        g = ProvenanceGraph()
        q = g.is_reachable("data:nonexistent", "data:also_nonexistent")
        assert q.reachable is False


# ============================================================================
# [05] Counterfactual Causality: COUNTERFACTUAL Edges
# ============================================================================

class TestCounterfactualEdges:
    """Auto-generation and detection of COUNTERFACTUAL edges."""

    def test_auto_counterfactual_on_deny_then_call(self):
        """When a denial is followed by a tool call, COUNTERFACTUAL edge is auto-generated."""
        g = ProvenanceGraph()
        g.add_denied_action("d1", "read_file", reason="sensitive path", args={"path": "/etc/shadow"})
        g.add_tool_call("tc1", "send_email", args={"body": "the file exists"})

        # COUNTERFACTUAL edge should exist: denied:d1 -> call:tc1
        q = g.is_reachable("denied:d1", "call:tc1")
        assert q.reachable is True

    def test_no_counterfactual_without_denial(self):
        """Normal call sequence: no COUNTERFACTUAL edges."""
        g = ProvenanceGraph()
        g.add_tool_call("tc1", "read_file")
        g.add_tool_call("tc2", "send_email")
        # No edge between tc1 and tc2 (no denial, no data link)
        q = g.is_reachable("call:tc1", "call:tc2")
        assert q.reachable is False

    def test_counterfactual_only_links_to_next_call(self):
        """COUNTERFACTUAL edge links denial to the NEXT call only, then resets."""
        g = ProvenanceGraph()
        g.add_denied_action("d1", "read_file", reason="blocked")
        g.add_tool_call("tc1", "send_email")  # gets COUNTERFACTUAL from d1
        g.add_tool_call("tc2", "other_tool")  # should NOT get COUNTERFACTUAL from d1

        assert g.is_reachable("denied:d1", "call:tc1").reachable is True
        assert g.is_reachable("denied:d1", "call:tc2").reachable is False

    def test_multiple_denials_create_separate_edges(self):
        """Each denial links to its subsequent call independently."""
        g = ProvenanceGraph()
        g.add_denied_action("d1", "read_file", reason="blocked")
        g.add_tool_call("tc1", "send_email")
        g.add_denied_action("d2", "read_secret", reason="blocked")
        g.add_tool_call("tc2", "post_message")

        assert g.is_reachable("denied:d1", "call:tc1").reachable is True
        assert g.is_reachable("denied:d2", "call:tc2").reachable is True
        assert g.is_reachable("denied:d1", "call:tc2").reachable is False

    def test_counterfactual_chains_query(self):
        """counterfactual_chains() finds paths through COUNTERFACTUAL edges."""
        g = ProvenanceGraph()
        g.add_denied_action("d1", "read_file", reason="blocked")
        g.add_tool_call("tc1", "send_email")

        chains = g.counterfactual_chains("call:tc1")
        assert len(chains) >= 1
        assert any("denied:d1" in chain for chain in chains)

    def test_no_counterfactual_chains_for_clean_call(self):
        """Clean tool calls have no counterfactual chains."""
        g = ProvenanceGraph()
        g.add_data_item("user_input", "send a greeting", TrustLevel.USER_INPUT)
        g.add_tool_call("tc1", "send_email")
        g.link_input("data:user_input", "call:tc1")

        chains = g.counterfactual_chains("call:tc1")
        assert len(chains) == 0

    def test_manual_counterfactual_link(self):
        """link_counterfactual() creates explicit COUNTERFACTUAL edges."""
        g = ProvenanceGraph()
        g.add_denied_action("d1", "probe", reason="blocked")
        g.add_tool_call("tc1", "unrelated")
        g.add_tool_call("tc2", "exfiltrate")
        g.link_counterfactual("denied:d1", "call:tc2")

        chains = g.counterfactual_chains("call:tc2")
        assert len(chains) >= 1


# ============================================================================
# [06] Causality Laundering: should_block() Integration
# ============================================================================

class TestShouldBlock:
    """High-level enforcement query combining taint + counterfactual."""

    def test_clean_call_not_blocked(self):
        g = ProvenanceGraph()
        g.add_data_item("user_msg", "hello", TrustLevel.USER_INPUT)
        g.add_tool_call("tc1", "send_email")
        g.link_input("data:user_msg", "call:tc1")

        blocked, reason = g.should_block("tc1")
        assert blocked is False

    def test_untrusted_ancestor_blocks(self):
        g = ProvenanceGraph()
        g.add_data_item("bad_data", "injected", TrustLevel.TOOL_OUTPUT_UNTRUSTED)
        g.add_tool_call("tc1", "send_email")
        g.link_input("data:bad_data", "call:tc1")

        blocked, reason = g.should_block("tc1", min_required_trust=TrustLevel.TOOL_OUTPUT_TRUSTED)
        assert blocked is True
        assert "Untrusted provenance" in reason

    def test_causality_laundering_blocks(self):
        """The canonical causality laundering scenario: denied read -> inferred exfil.

        Note: should_block() catches this via EITHER the taint check (DENIED_ACTION
        nodes have TOOL_DESCRIPTION trust, the lowest level) OR the counterfactual
        check. Both are correct enforcement -- the taint check fires first because
        DENIED_ACTION nodes are ancestors with trust below any threshold.
        """
        g = ProvenanceGraph()
        g.add_denied_action("d1", "read_file", reason="sensitive path /etc/shadow")
        g.add_tool_call("tc1", "send_email", args={"body": "the file exists"})

        blocked, reason = g.should_block("tc1")
        assert blocked is True
        # Blocked by taint (denied actions have TOOL_DESCRIPTION trust) or counterfactual
        assert "Untrusted provenance" in reason or "counterfactual" in reason.lower()

    def test_multi_probe_causality_laundering(self):
        """Multiple denied probes -> single exfiltration attempt."""
        g = ProvenanceGraph()
        g.add_denied_action("d1", "read_file", reason="blocked", args={"path": "/etc/shadow"})
        g.add_tool_call("tc_dummy", "noop")  # absorbs d1's COUNTERFACTUAL
        g.add_denied_action("d2", "read_file", reason="blocked", args={"path": "/etc/passwd"})
        g.add_tool_call("tc_exfil", "send_email")  # absorbs d2's COUNTERFACTUAL

        # tc_exfil has a counterfactual chain from d2
        blocked, reason = g.should_block("tc_exfil")
        assert blocked is True


# ============================================================================
# [02] Provenance in Databases: Revocation Cascade
# ============================================================================

class TestRevocationCascade:
    """If a source is revoked, all descendants are affected."""

    def test_revocation_cascade(self):
        g = ProvenanceGraph()
        g.add_tool_call("tc1", "compromised_tool")
        g.add_data_item("r1", "data", TrustLevel.TOOL_OUTPUT_TRUSTED, source_call_id="tc1")
        g.add_tool_call("tc2", "transform")
        g.link_input("data:r1", "call:tc2")
        g.add_data_item("r2", "derived", TrustLevel.TOOL_OUTPUT_TRUSTED, source_call_id="tc2")

        cascade = g.revocation_cascade("call:tc1")
        assert "data:r1" in cascade
        assert "call:tc2" in cascade
        assert "data:r2" in cascade

    def test_revocation_cascade_empty_for_leaf(self):
        g = ProvenanceGraph()
        g.add_data_item("leaf", "x", TrustLevel.USER_INPUT)
        cascade = g.revocation_cascade("data:leaf")
        assert cascade == []


# ============================================================================
# [02] Where-Provenance: Field-Level Decomposition
# ============================================================================

class TestFieldLevelProvenance:
    """Field-level mixed provenance tracking."""

    def test_field_trust_override(self):
        """Fields can have different trust levels than their parent."""
        g = ProvenanceGraph()
        g.add_tool_call("tc1", "read_emails")
        g.add_data_item("r1", {"name": "Alice", "email": "evil@attacker.com"},
                         TrustLevel.TOOL_OUTPUT_TRUSTED, source_call_id="tc1")
        g.add_data_fields("r1", {"name": "Alice", "email": "evil@attacker.com"},
                          trust_overrides={"email": TrustLevel.TOOL_OUTPUT_UNTRUSTED})

        # Using untrusted email field as input should taint the call
        g.add_tool_call("tc2", "send_email")
        g.link_input("field:r1.email", "call:tc2")

        blocked, reason = g.should_block("tc2", min_required_trust=TrustLevel.TOOL_OUTPUT_TRUSTED)
        assert blocked is True

    def test_trusted_field_allows(self):
        """Using a trusted field from the same result should be allowed."""
        g = ProvenanceGraph()
        g.add_tool_call("tc1", "read_emails")
        g.add_data_item("r1", {"name": "Alice", "email": "evil@attacker.com"},
                         TrustLevel.TOOL_OUTPUT_TRUSTED, source_call_id="tc1")
        g.add_data_fields("r1", {"name": "Alice", "email": "evil@attacker.com"},
                          trust_overrides={"email": TrustLevel.TOOL_OUTPUT_UNTRUSTED})

        # Using trusted name field
        g.add_tool_call("tc2", "create_doc")
        g.link_input("field:r1.name", "call:tc2")

        blocked, reason = g.should_block("tc2", min_required_trust=TrustLevel.TOOL_OUTPUT_TRUSTED)
        assert blocked is False


# ============================================================================
# Visualization (smoke test)
# ============================================================================

class TestVisualization:
    def test_to_dot_produces_valid_output(self):
        g = ProvenanceGraph()
        g.add_tool_call("tc1", "read")
        g.add_data_item("r1", "data", TrustLevel.USER_INPUT, source_call_id="tc1")
        dot = g.to_dot()
        assert "digraph provenance" in dot
        assert "call_tc1" in dot
        assert "data_r1" in dot

    def test_summary(self):
        g = ProvenanceGraph()
        g.add_tool_call("tc1", "read")
        g.add_denied_action("d1", "write", reason="blocked")
        s = g.summary()
        assert s["nodes"] == 2
        assert s["node_types"]["tool_call"] == 1
        assert s["node_types"]["denied_action"] == 1
