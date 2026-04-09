"""
Audit Log — mandatory, tamper-evident record of every ARM decision.

Every tool call that passes through ARM is logged — both ALLOW and DENY.
You can't bypass the audit trail because you can't bypass ARM.

Hash-chaining provides tamper evidence: each entry includes the hash
of the previous entry. Modifying any entry breaks the chain.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from arm_core.policy_engine import PolicyDecision


@dataclass
class AuditEntry:
    """A single audit log entry."""

    timestamp: float
    session_id: str
    tool_name: str
    args: dict[str, Any]
    decision: str  # "allow" or "deny"
    reason: str
    previous_hash: str
    entry_hash: str = ""
    # Layer-by-layer trace (populated by LayeredPolicyEngine; empty list for old PolicyEngine)
    layer_results: list[dict] = field(default_factory=list)

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this entry (excluding entry_hash itself)."""
        data = json.dumps(
            {
                "timestamp": self.timestamp,
                "session_id": self.session_id,
                "tool_name": self.tool_name,
                "args": self.args,
                "decision": self.decision,
                "reason": self.reason,
                "previous_hash": self.previous_hash,
                "layer_results": self.layer_results,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> dict:
        d = {
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "args": self._sanitize_args(self.args),
            "decision": self.decision,
            "reason": self.reason,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }
        if self.layer_results:
            d["layer_results"] = self.layer_results
        return d

    @staticmethod
    def _sanitize_args(args: dict[str, Any]) -> dict[str, Any]:
        """Truncate long argument values for logging (prevent log flooding)."""
        sanitized = {}
        for k, v in args.items():
            s = str(v)
            sanitized[k] = s[:200] + f"...({len(s)} chars)" if len(s) > 200 else s
        return sanitized


class AuditLog:
    """
    Hash-chained audit log. Append-only.

    Every ARM decision (allow or deny) is recorded with:
    - What was requested (tool name, args)
    - What ARM decided (allow/deny + reason)
    - Hash chain link to previous entry (tamper evidence)
    """

    def __init__(self, session_id: str, log_file: str | None = None):
        self.session_id = session_id
        self.log_file = log_file
        self.entries: list[AuditEntry] = []
        self._last_hash = "GENESIS"

    def record(self, decision: PolicyDecision) -> AuditEntry:
        """Record a policy decision in the audit log."""
        # Extract layer results if present (LayeredPolicyEngine populates these)
        layer_results_serialized: list[dict] = []
        for lr in getattr(decision, "layer_results", ()):
            layer_results_serialized.append(
                {
                    "layer": lr.layer_name,
                    "verdict": lr.verdict.value,
                    "reason": lr.reason,
                }
            )

        entry = AuditEntry(
            timestamp=time.time(),
            session_id=self.session_id,
            tool_name=decision.tool_name,
            args=decision.args,
            decision=decision.decision.value,
            reason=decision.reason,
            previous_hash=self._last_hash,
            layer_results=layer_results_serialized,
        )
        entry.entry_hash = entry.compute_hash()
        self._last_hash = entry.entry_hash

        self.entries.append(entry)

        if self.log_file:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry.to_dict(), default=str) + "\n")

        return entry

    def verify_chain(self) -> bool:
        """Verify the hash chain is intact (no tampering)."""
        expected_prev = "GENESIS"
        for entry in self.entries:
            if entry.previous_hash != expected_prev:
                return False
            if entry.entry_hash != entry.compute_hash():
                return False
            expected_prev = entry.entry_hash
        return True

    def summary(self) -> dict:
        """Return a summary of all decisions."""
        allows = sum(1 for e in self.entries if e.decision == "allow")
        denies = sum(1 for e in self.entries if e.decision == "deny")
        return {
            "total": len(self.entries),
            "allowed": allows,
            "denied": denies,
            "chain_valid": self.verify_chain(),
            "denied_tools": [
                {"tool": e.tool_name, "reason": e.reason}
                for e in self.entries
                if e.decision == "deny"
            ],
        }
