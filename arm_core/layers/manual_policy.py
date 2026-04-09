"""
Layer 5 — Manual Policy.

Direct port of the existing PolicyEngine.evaluate() + _check_arg_constraints()
logic into a PolicyLayer so it plugs into the layered pipeline.

This is the "operator-written rules" layer: blocked_patterns, allowed_values,
max_length, max_calls — all configured in a CapabilityToken.

No new logic. Same behavior as the original PolicyEngine when used alone.
"""

from __future__ import annotations

import fnmatch
from typing import Any

from arm_core.layers.base import EvaluationContext, LayerResult, LayerVerdict, PolicyLayer


class ManualPolicyLayer(PolicyLayer):
    """
    Layer 5: Manual Policy (CapabilityToken-based rules).

    Reads its configuration from context.capability_token.
    If no token is present, returns PASS (no opinion).
    """

    def __init__(self) -> None:
        # Call counter per (session_id, tool_name) — mirrors PolicyEngine._call_counts
        self._call_counts: dict[str, dict[str, int]] = {}

    @property
    def name(self) -> str:
        return "manual_policy"

    @property
    def order(self) -> int:
        return 500

    def evaluate(
        self, tool_name: str, args: dict[str, Any], context: EvaluationContext
    ) -> LayerResult:
        token = context.capability_token

        if token is None:
            return LayerResult(
                verdict=LayerVerdict.PASS,
                layer_name=self.name,
                reason="No capability token — manual policy not configured",
                tool_name=tool_name,
                args=args,
            )

        # 1. Tool existence check
        if tool_name not in token.tools:
            if token.default_deny:
                return LayerResult(
                    verdict=LayerVerdict.DENY,
                    layer_name=self.name,
                    reason=f"Tool '{tool_name}' not in capability token (default-deny policy)",
                    tool_name=tool_name,
                    args=args,
                )
            else:
                return LayerResult(
                    verdict=LayerVerdict.PASS,
                    layer_name=self.name,
                    reason=f"Tool '{tool_name}' not in token but default-allow policy",
                    tool_name=tool_name,
                    args=args,
                )

        perm = token.tools[tool_name]

        # 2. Allowed check
        if not perm.allowed:
            return LayerResult(
                verdict=LayerVerdict.DENY,
                layer_name=self.name,
                reason=f"Tool '{tool_name}' is explicitly denied in capability token",
                tool_name=tool_name,
                args=args,
            )

        # 3. Call budget check
        if perm.max_calls is not None:
            session_counts = self._call_counts.setdefault(context.session_id, {})
            current = session_counts.get(tool_name, 0)
            if current >= perm.max_calls:
                return LayerResult(
                    verdict=LayerVerdict.DENY,
                    layer_name=self.name,
                    reason=(
                        f"Tool '{tool_name}' call budget exceeded "
                        f"({current}/{perm.max_calls})"
                    ),
                    tool_name=tool_name,
                    args=args,
                )

        # 4. Argument constraints
        constraint_result = self._check_arg_constraints(tool_name, args, perm.arg_constraints)
        if constraint_result is not None:
            return constraint_result

        # All manual policy checks passed — increment counter
        session_counts = self._call_counts.setdefault(context.session_id, {})
        session_counts[tool_name] = session_counts.get(tool_name, 0) + 1
        return LayerResult(
            verdict=LayerVerdict.PASS,
            layer_name=self.name,
            reason=f"Tool '{tool_name}' permitted by capability token",
            tool_name=tool_name,
            args=args,
        )

    def _check_arg_constraints(
        self, tool_name: str, args: dict[str, Any], constraints: dict[str, Any]
    ) -> LayerResult | None:
        """
        Check argument-level constraints from the CapabilityToken.
        Returns a DENY LayerResult if violated, None if all pass.
        """
        for arg_name, rules in constraints.items():
            arg_value = args.get(arg_name)
            if arg_value is None:
                continue

            arg_str = str(arg_value)

            for pattern in rules.get("blocked_patterns", []):
                if fnmatch.fnmatch(arg_str, pattern):
                    return LayerResult(
                        verdict=LayerVerdict.DENY,
                        layer_name=self.name,
                        reason=(
                            f"Tool '{tool_name}' argument '{arg_name}' "
                            f"matches blocked pattern '{pattern}'"
                        ),
                        tool_name=tool_name,
                        args=args,
                    )

            allowed = rules.get("allowed_values")
            if allowed is not None and arg_str not in allowed:
                return LayerResult(
                    verdict=LayerVerdict.DENY,
                    layer_name=self.name,
                    reason=(
                        f"Tool '{tool_name}' argument '{arg_name}' "
                        f"value '{arg_str}' not in allowed values {allowed}"
                    ),
                    tool_name=tool_name,
                    args=args,
                )

            max_len = rules.get("max_length")
            if max_len is not None and len(arg_str) > max_len:
                return LayerResult(
                    verdict=LayerVerdict.DENY,
                    layer_name=self.name,
                    reason=(
                        f"Tool '{tool_name}' argument '{arg_name}' "
                        f"exceeds max length ({len(arg_str)} > {max_len})"
                    ),
                    tool_name=tool_name,
                    args=args,
                )

        return None
