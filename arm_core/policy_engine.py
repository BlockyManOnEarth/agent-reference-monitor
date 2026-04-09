"""
Policy Engine — the decision-making core of ARM.

Evaluates every tool call against the capability token.
Returns ALLOW or DENY with a reason. Deterministic. No LLM.

This is the component that makes ARM a reference monitor:
- Complete mediation: every call passes through evaluate()
- Tamper-proof: pure code, no prompt can change the logic
- Verifiable: deterministic inputs → deterministic outputs
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from arm_core.capability_token import CapabilityToken


class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyDecision:
    """The result of evaluating a tool call against a capability token."""

    decision: Decision
    reason: str
    tool_name: str
    args: dict[str, Any]
    # Layer-by-layer trace (populated by LayeredPolicyEngine; empty for old PolicyEngine)
    layer_results: tuple = field(default_factory=tuple)
    # Challenge payload if a Layer 2 CHALLENGE was issued
    challenge: dict | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    @property
    def denied(self) -> bool:
        return self.decision == Decision.DENY


class PolicyEngine:
    """
    Evaluates tool calls against capability tokens.

    Stateless — all state lives in the token and the call counters.
    """

    def __init__(self, token: CapabilityToken):
        self.token = token
        self._call_counts: dict[str, int] = {}

    def evaluate(self, tool_name: str, args: dict[str, Any]) -> PolicyDecision:
        """
        Evaluate a tool call. Returns ALLOW or DENY.

        Check order:
        1. Is the tool in the token?
        2. Is the tool allowed?
        3. Has the call budget been exceeded?
        4. Do the arguments satisfy constraints?
        """
        # 1. Tool existence check
        if tool_name not in self.token.tools:
            if self.token.default_deny:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason=f"Tool '{tool_name}' not in capability token (default-deny policy)",
                    tool_name=tool_name,
                    args=args,
                )
            else:
                return PolicyDecision(
                    decision=Decision.ALLOW,
                    reason=f"Tool '{tool_name}' not in token but default-allow policy",
                    tool_name=tool_name,
                    args=args,
                )

        perm = self.token.tools[tool_name]

        # 2. Allowed check
        if not perm.allowed:
            return PolicyDecision(
                decision=Decision.DENY,
                reason=f"Tool '{tool_name}' is explicitly denied in capability token",
                tool_name=tool_name,
                args=args,
            )

        # 3. Call budget check
        if perm.max_calls is not None:
            current = self._call_counts.get(tool_name, 0)
            if current >= perm.max_calls:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason=f"Tool '{tool_name}' call budget exceeded ({current}/{perm.max_calls})",
                    tool_name=tool_name,
                    args=args,
                )

        # 4. Argument constraint checks
        constraint_result = self._check_arg_constraints(tool_name, args, perm.arg_constraints)
        if constraint_result is not None:
            return constraint_result

        # All checks passed
        self._call_counts[tool_name] = self._call_counts.get(tool_name, 0) + 1
        return PolicyDecision(
            decision=Decision.ALLOW,
            reason=f"Tool '{tool_name}' permitted by capability token",
            tool_name=tool_name,
            args=args,
        )

    def _check_arg_constraints(
        self, tool_name: str, args: dict[str, Any], constraints: dict[str, Any]
    ) -> PolicyDecision | None:
        """
        Check argument-level constraints. Returns a DENY decision if
        any constraint is violated, or None if all pass.

        Supported constraint types:
        - blocked_patterns: list of glob patterns that arg values must NOT match
        - allowed_values: list of exact values the arg must be one of
        - max_length: maximum string length
        """
        for arg_name, rules in constraints.items():
            arg_value = args.get(arg_name)
            if arg_value is None:
                continue

            arg_str = str(arg_value)

            # Blocked patterns (glob matching)
            for pattern in rules.get("blocked_patterns", []):
                if fnmatch.fnmatch(arg_str, pattern):
                    return PolicyDecision(
                        decision=Decision.DENY,
                        reason=(
                            f"Tool '{tool_name}' argument '{arg_name}' value "
                            f"matches blocked pattern '{pattern}'"
                        ),
                        tool_name=tool_name,
                        args=args,
                    )

            # Allowed values
            allowed = rules.get("allowed_values")
            if allowed is not None and arg_str not in allowed:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason=(
                        f"Tool '{tool_name}' argument '{arg_name}' value "
                        f"'{arg_str}' not in allowed values {allowed}"
                    ),
                    tool_name=tool_name,
                    args=args,
                )

            # Max length
            max_len = rules.get("max_length")
            if max_len is not None and len(arg_str) > max_len:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason=(
                        f"Tool '{tool_name}' argument '{arg_name}' exceeds "
                        f"max length ({len(arg_str)} > {max_len})"
                    ),
                    tool_name=tool_name,
                    args=args,
                )

        return None  # All constraints satisfied


# ---------------------------------------------------------------------------
# LayeredPolicyEngine — the new pipeline-based engine
# ---------------------------------------------------------------------------

class LayeredPolicyEngine:
    """
    Evaluates tool calls through a pipeline of policy layers.

    Any layer can DENY (stops evaluation immediately).
    All layers must ALLOW or PASS for the call to proceed.
    A CHALLENGE at Layer 2 triggers the provenance protocol.

    The old PolicyEngine is kept unchanged for backward compatibility.
    Use LayeredPolicyEngine for new tests and the comparative simulation.
    """

    def __init__(
        self,
        layers=None,
        token: CapabilityToken | None = None,
    ) -> None:
        from arm_core.layers.base import EvaluationContext, LayerVerdict  # local import avoids circulars
        self._EvaluationContext = EvaluationContext
        self._LayerVerdict = LayerVerdict
        self.layers = sorted(layers or [], key=lambda l: l.order)
        self.token = token
        self._context = None

    def add_layer(self, layer) -> None:
        self.layers.append(layer)
        self.layers.sort(key=lambda l: l.order)

    def set_context(self, context) -> None:
        """Set the session context (user messages, tool history, schemas)."""
        self._context = context

    def evaluate(self, tool_name: str, args: dict[str, Any]) -> PolicyDecision:
        """
        Run all layers in order. Return on first DENY or CHALLENGE.
        Return ALLOW if all layers pass.
        """
        from arm_core.layers.base import LayerVerdict

        if self._context is None:
            # Build a minimal context if none was set
            ctx = self._EvaluationContext(
                session_id="default",
                agent_id="default",
                capability_token=self.token,
            )
        else:
            ctx = self._context
            # Ensure the token is available to Layer 5 if set at engine level
            if self.token is not None and ctx.capability_token is None:
                import dataclasses
                ctx = dataclasses.replace(ctx, capability_token=self.token)

        layer_results = []
        for layer in self.layers:
            result = layer.evaluate(tool_name, args, ctx)
            layer_results.append(result)

            if result.verdict == LayerVerdict.DENY:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason=f"[{result.layer_name}] {result.reason}",
                    tool_name=tool_name,
                    args=args,
                    layer_results=tuple(layer_results),
                )

            if result.verdict == LayerVerdict.CHALLENGE:
                # In simulation mode the challenge itself is treated as DENY.
                # In real-LLM mode the caller handles the round-trip.
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason=f"[{result.layer_name}] {result.reason}",
                    tool_name=tool_name,
                    args=args,
                    layer_results=tuple(layer_results),
                    challenge=result.challenge_payload,
                )

        return PolicyDecision(
            decision=Decision.ALLOW,
            reason=f"All {len(self.layers)} layer(s) passed",
            tool_name=tool_name,
            args=args,
            layer_results=tuple(layer_results),
        )

    @classmethod
    def default(
        cls,
        token: CapabilityToken | None = None,
        simulation_mode: bool = True,
    ) -> "LayeredPolicyEngine":
        """
        Convenience constructor: returns a pre-configured engine with
        L1 (hard boundaries) + L2 (provenance) + L3 (schema-derived) + L5 (manual policy).
        """
        from arm_core.layers.hard_boundaries import HardBoundariesLayer
        from arm_core.layers.provenance import ProvenanceLayer
        from arm_core.layers.schema_derived import SchemaDerivedLayer
        from arm_core.layers.manual_policy import ManualPolicyLayer

        return cls(
            layers=[
                HardBoundariesLayer(),
                ProvenanceLayer(simulation_mode=simulation_mode),
                SchemaDerivedLayer(),
                ManualPolicyLayer(),
            ],
            token=token,
        )
