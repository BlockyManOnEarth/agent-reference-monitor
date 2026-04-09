"""
Base interfaces for ARM policy layers.

Every layer implements PolicyLayer and returns a LayerResult.
Layers share an EvaluationContext that carries session state.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from arm_core.capability_token import CapabilityToken


class LayerVerdict(Enum):
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"  # Layer 2 only — provenance unclear, needs justification
    PASS = "pass"            # This layer has no opinion — defer to next layer


@dataclass(frozen=True)
class LayerResult:
    """Result returned by a single policy layer."""

    verdict: LayerVerdict
    layer_name: str
    reason: str
    tool_name: str
    args: dict[str, Any]
    # For CHALLENGE verdict: the structured challenge payload sent back to the LLM
    challenge_payload: dict | None = None


class PolicyLayer(ABC):
    """Base class for all ARM policy layers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable layer name (e.g., 'hard_boundaries')."""
        ...

    @property
    @abstractmethod
    def order(self) -> int:
        """Evaluation order. Lower = evaluated first.
        L1=100, L2=200, L3=300, L4=400, L5=500."""
        ...

    @abstractmethod
    def evaluate(
        self, tool_name: str, args: dict[str, Any], context: EvaluationContext
    ) -> LayerResult:
        """Evaluate a tool call. Return ALLOW, DENY, CHALLENGE, or PASS."""
        ...


@dataclass
class EvaluationContext:
    """
    Shared context passed through all layers during evaluation.

    Set once per session by LayeredPolicyEngine.set_context().
    Layers read from it — they do NOT write to it.
    """

    session_id: str
    agent_id: str

    # Session history — required by Layer 2 (provenance)
    user_messages: list[dict] = field(default_factory=list)
    # Each entry: {"role": "user", "content": "..."}

    tool_call_history: list[dict] = field(default_factory=list)
    # Each entry: {"tool": str, "args": dict, "result": any, "decision": "allow"|"deny"}

    system_prompt: str | None = None

    # Tool schemas — required by Layer 3 (schema-derived)
    # tool_name -> MCP inputSchema dict
    tool_schemas: dict[str, dict] | None = None

    # Manual policy token — required by Layer 5
    capability_token: CapabilityToken | None = None
