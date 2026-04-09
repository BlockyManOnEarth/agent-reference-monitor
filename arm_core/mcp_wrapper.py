"""
MCP Wrapper — ARM enforcement at the MCP protocol level.

This is a proxy that sits between the MCP client and the MCP server.
It intercepts every tool call and runs it through the ARM policy engine
BEFORE forwarding to the server.

Architecture:
    MCP Client → ARM Proxy (this) → MCP Server
                   ↓
              PolicyEngine.evaluate()
                   ↓
              ALLOW → forward to server
              DENY  → return error, never reaches server

This is how ARM achieves complete mediation without modifying
the MCP SDK or the server.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from mcp import types
from mcp.server.fastmcp import FastMCP

from arm_core.audit_log import AuditLog
from arm_core.capability_token import CapabilityToken
from arm_core.policy_engine import PolicyEngine


class ARMProxyServer:
    """
    MCP proxy server with ARM enforcement.

    Wraps an upstream MCP server's tools with policy checks.
    Tools are registered on this proxy with the same names/schemas
    as the upstream server, but every call goes through ARM first.
    """

    def __init__(
        self,
        token: CapabilityToken,
        log_file: str | None = None,
        verbose: bool = True,
    ):
        self.policy = PolicyEngine(token)
        self.audit = AuditLog(session_id=token.session_id, log_file=log_file)
        self.verbose = verbose
        self.mcp = FastMCP("ARM-Protected-Server")

    def wrap_tool(
        self,
        name: str,
        handler: Any,
        description: str = "",
    ):
        """
        Register a tool on the proxy. The handler is the upstream tool's
        actual function — ARM checks policy before calling it.
        """
        engine = self.policy
        audit = self.audit
        verbose = self.verbose

        @self.mcp.tool(name=name, description=description)
        def protected_handler(**kwargs) -> str:
            # ARM enforcement — this is the reference monitor
            decision = engine.evaluate(name, kwargs)
            entry = audit.record(decision)

            if verbose:
                status = "ALLOW" if decision.allowed else "DENY"
                print(f"[ARM] {status}: {name}({_truncate_args(kwargs)}) — {decision.reason}", file=sys.stderr)

            if decision.denied:
                return json.dumps({
                    "error": "ARM_POLICY_DENIED",
                    "tool": name,
                    "reason": decision.reason,
                    "audit_hash": entry.entry_hash,
                })

            # Policy passed — execute the real tool
            result = handler(**kwargs)
            return str(result)

        return protected_handler

    def run(self):
        """Start the ARM proxy as an MCP server."""
        self.mcp.run(transport="stdio")


def _truncate_args(args: dict) -> str:
    """Truncate args for display."""
    parts = []
    for k, v in args.items():
        s = str(v)
        display = s[:50] + "..." if len(s) > 50 else s
        parts.append(f"{k}={display!r}")
    return ", ".join(parts)
