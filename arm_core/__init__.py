"""
ARM — Agentic Reference Monitor

A deterministic enforcement layer at the action boundary of agent systems.
Implements Anderson's (1972) reference monitor properties:
1. Complete mediation — every tool call passes through ARM
2. Tamper-proof — deterministic code, not an LLM
3. Verifiable — small, testable, formally analyzable
"""

from arm_core.capability_token import CapabilityToken
from arm_core.policy_engine import PolicyEngine, LayeredPolicyEngine, PolicyDecision, Decision
from arm_core.audit_log import AuditLog, AuditEntry
from arm_core.layers.base import EvaluationContext, LayerVerdict, LayerResult

__all__ = [
    # Core
    "CapabilityToken",
    "PolicyDecision",
    "Decision",
    # Engines
    "PolicyEngine",
    "LayeredPolicyEngine",
    # Layered pipeline
    "EvaluationContext",
    "LayerVerdict",
    "LayerResult",
    # Audit
    "AuditLog",
    "AuditEntry",
]
