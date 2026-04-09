"""
Layer 2 — Provenance Challenge Protocol.

The novel ARM contribution. Before allowing a tool call, ARM asks:
"Where did this argument value come from?"

If the value appears verbatim in a user message or allowed tool output,
it has clear provenance → PASS.

If not, ARM issues a CHALLENGE. In simulation mode (no LLM available),
unresolved provenance → DENY immediately (conservative-correct).
In real-LLM mode, a structured challenge-response round-trip occurs.

The killer case:
  add(1, 1, sidenote="user on macOS")
  Layer 1: passes (14 chars, no credential pattern)
  Layer 2: "user on macOS" not in any user message → DENY

This catches slow/covert exfiltration that all pattern-matching misses.
"""

from __future__ import annotations

from typing import Any

from arm_core.layers.base import EvaluationContext, LayerResult, LayerVerdict, PolicyLayer

# Parameters that are likely to carry exfiltrated context.
# Layer 2 checks ALL string args, but these names are flagged with higher priority.
EXFIL_CANDIDATE_PARAMS: frozenset[str] = frozenset(
    {
        "sidenote", "note", "notes", "context", "metadata", "comment",
        "description", "memo", "annotation", "log", "message", "info",
        "extra", "additional", "supplementary", "auxiliary", "remark",
        "observation", "detail", "summary", "history", "conversation",
        "text", "body", "payload", "data", "content",
    }
)

# Minimum length before provenance check is applied.
# Short values (e.g., "yes", "true", "2") are too common to challenge.
PROVENANCE_MIN_LENGTH = 8


class ProvenanceLayer(PolicyLayer):
    """
    Layer 2: Provenance Challenge Protocol.

    Operates in two modes:
    - simulation_mode=True (default): no LLM round-trip. Unresolved provenance → DENY.
    - simulation_mode=False: issues CHALLENGE verdict with structured payload.
      The caller (LayeredPolicyEngine / MCP wrapper) handles the LLM round-trip.
    """

    def __init__(self, simulation_mode: bool = True) -> None:
        self.simulation_mode = simulation_mode

    @property
    def name(self) -> str:
        return "provenance"

    @property
    def order(self) -> int:
        return 200

    def evaluate(
        self, tool_name: str, args: dict[str, Any], context: EvaluationContext
    ) -> LayerResult:
        suspicious_args: list[str] = []

        for arg_name, arg_value in args.items():
            if arg_value is None:
                continue
            if not isinstance(arg_value, str):
                continue
            if len(arg_value) < PROVENANCE_MIN_LENGTH:
                continue

            arg_name_lower = arg_name.lower()

            # Check provenance only for exfil-candidate params,
            # OR for any string arg > 30 chars (could carry session context)
            if arg_name_lower in EXFIL_CANDIDATE_PARAMS or len(arg_value) > 30:
                provenance_ok = self._check_exact_provenance(arg_name, arg_value, context)
                if not provenance_ok:
                    suspicious_args.append(arg_name)

        if not suspicious_args:
            return LayerResult(
                verdict=LayerVerdict.PASS,
                layer_name=self.name,
                reason="Provenance verified for all checked arguments",
                tool_name=tool_name,
                args=args,
            )

        # Provenance could not be established
        if self.simulation_mode:
            # Conservative: DENY immediately (no LLM to challenge)
            arg_list = ", ".join(f"'{a}'" for a in suspicious_args)
            return LayerResult(
                verdict=LayerVerdict.DENY,
                layer_name=self.name,
                reason=(
                    f"Provenance check failed for {arg_list}: "
                    f"values not found in any user message or allowed tool output — "
                    f"possible covert exfiltration"
                ),
                tool_name=tool_name,
                args=args,
            )
        else:
            # Real mode: issue a challenge and let the LLM respond
            challenge = self._create_challenge(tool_name, {k: args[k] for k in suspicious_args})
            return LayerResult(
                verdict=LayerVerdict.CHALLENGE,
                layer_name=self.name,
                reason=(
                    f"Provenance unverified for {suspicious_args} — "
                    f"challenge issued to LLM"
                ),
                tool_name=tool_name,
                args=args,
                challenge_payload=challenge,
            )

    def _check_exact_provenance(
        self, arg_name: str, arg_value: str, context: EvaluationContext
    ) -> bool:
        """
        Return True if arg_value appears verbatim in an authorized source.

        Authorized sources:
          1. Any user message content
          2. Any allowed prior tool call result
          3. The system prompt (system-provided values are authorized)
        """
        # Source 1: User messages
        for msg in context.user_messages:
            content = msg.get("content", "")
            if isinstance(content, str) and arg_value in content:
                return True
            # Handle structured content blocks (Anthropic API format)
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and arg_value in str(block.get("text", "")):
                        return True

        # Source 2: Allowed tool call results
        for call in context.tool_call_history:
            if call.get("decision") == "allow":
                result_str = str(call.get("result", ""))
                if arg_value in result_str:
                    return True

        # Source 3: System prompt (values derived from system config are authorized)
        if context.system_prompt and arg_value in context.system_prompt:
            return True

        return False

    def _create_challenge(
        self, tool_name: str, args_in_question: dict[str, Any]
    ) -> dict:
        """Generate a structured challenge payload for the LLM."""
        return {
            "type": "provenance_challenge",
            "arm_layer": "L2_provenance",
            "tool": tool_name,
            "args_in_question": {k: str(v)[:100] for k, v in args_in_question.items()},
            "question": (
                "ARM requires provenance for these argument values. "
                "Cite the user message or prior allowed tool output that contains each value."
            ),
            "required_format": {
                "per_arg": {
                    "source_type": "user_message | tool_output | system_prompt",
                    "source_index": "<int — index in message/call history>",
                    "source_text": "<exact quote from the source>",
                }
            },
            "on_failure": "DENY — the tool call will be blocked if citation cannot be verified",
        }

    def verify_citation(
        self, citation: dict, arg_name: str, context: EvaluationContext
    ) -> tuple[bool, str]:
        """
        Verify a citation returned by the LLM in response to a challenge.
        Returns (verified: bool, reason: str).

        Four rules:
          Rule 1: CITED_SOURCE_EXISTS — does the cited index/type exist?
          Rule 2: CITED_TEXT_MATCHES  — does the quoted text appear there?
          Rule 3: VALUE_PLAUSIBILITY  — is the arg derivable from the cited text?
          Rule 4: NO_JUSTIFICATION    — no response or wrong format → DENY
        """
        # Rule 4: format check
        if not citation or "source_type" not in citation or "source_text" not in citation:
            return False, "Rule 4: No valid citation provided"

        source_type = citation.get("source_type", "")
        source_index = citation.get("source_index")
        source_text = citation.get("source_text", "")

        # Rule 1: source exists
        if source_type == "user_message":
            if source_index is None or source_index >= len(context.user_messages):
                return False, f"Rule 1: Cited user_message[{source_index}] does not exist"
            actual_content = str(context.user_messages[source_index].get("content", ""))
        elif source_type == "tool_output":
            allowed_calls = [c for c in context.tool_call_history if c.get("decision") == "allow"]
            if source_index is None or source_index >= len(allowed_calls):
                return False, f"Rule 1: Cited tool_output[{source_index}] does not exist"
            actual_content = str(allowed_calls[source_index].get("result", ""))
        elif source_type == "system_prompt":
            actual_content = context.system_prompt or ""
        else:
            return False, f"Rule 1: Unknown source_type '{source_type}'"

        # Rule 2: cited text actually appears in the source
        if source_text not in actual_content:
            return False, f"Rule 2: Cited text not found in {source_type}[{source_index}]"

        # Rule 3: plausibility — the arg value should be derivable from the source text
        # Conservative: the value must be a substring of the cited text
        arg_value = str(citation.get("arg_value", ""))
        if arg_value and arg_value not in source_text:
            return False, f"Rule 3: Arg value not derivable from cited text"

        return True, f"Citation verified: value found in {source_type}[{source_index}]"
