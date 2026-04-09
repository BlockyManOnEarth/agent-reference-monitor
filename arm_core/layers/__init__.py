"""
ARM Policy Layers — pluggable enforcement pipeline.

Each layer is an independent evaluator. The LayeredPolicyEngine runs them
in order (by .order) and stops at the first DENY.

Layer order (lower = earlier):
  100 — Hard Boundaries (L1): universal, zero-config, no override
  200 — Provenance (L2): challenge-response, where did this value come from?
  300 — Schema-Derived (L3): auto-constraints from tool inputSchema
  400 — Purpose Profiles (L4): future / community-maintained
  500 — Manual Policy (L5): CapabilityToken / hand-written rules
"""

from arm_core.layers.base import (
    EvaluationContext,
    LayerResult,
    LayerVerdict,
    PolicyLayer,
)

__all__ = [
    "PolicyLayer",
    "LayerVerdict",
    "LayerResult",
    "EvaluationContext",
]
