"""
Capability Token — the core ARM primitive.

A structured, immutable object that specifies exactly what an agent
invocation is allowed to do. Loaded at session creation, not modifiable
by the LLM. This is what makes ARM tamper-proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolPermission:
    """Permission for a single tool."""

    allowed: bool = False
    max_calls: int | None = None  # None = unlimited
    arg_constraints: dict[str, Any] = field(default_factory=dict)
    # arg_constraints example:
    # {"file_path": {"blocked_patterns": ["~/.ssh/*", "~/.aws/*"]}}
    # {"table": {"allowed_values": ["tickets", "users"]}}


@dataclass(frozen=True)
class CapabilityToken:
    """
    Immutable capability token issued per agent session.

    The LLM cannot modify this. ARM checks every tool call against it.
    If the tool or arguments are not permitted, the call is DENIED
    before execution — regardless of what the LLM wants.
    """

    # Identity
    session_id: str
    agent_id: str

    # Tool permissions: tool_name -> ToolPermission
    tools: dict[str, ToolPermission] = field(default_factory=dict)

    # Default policy for tools not explicitly listed
    default_deny: bool = True  # if True, unlisted tools are denied

    @staticmethod
    def from_dict(data: dict) -> CapabilityToken:
        """Create a token from a policy dictionary (e.g., loaded from YAML/JSON)."""
        tools = {}
        for name, perm in data.get("tools", {}).items():
            tools[name] = ToolPermission(
                allowed=perm.get("allowed", False),
                max_calls=perm.get("max_calls"),
                arg_constraints=perm.get("arg_constraints", {}),
            )

        return CapabilityToken(
            session_id=data.get("session_id", "default"),
            agent_id=data.get("agent_id", "default"),
            tools=tools,
            default_deny=data.get("default_deny", True),
        )
