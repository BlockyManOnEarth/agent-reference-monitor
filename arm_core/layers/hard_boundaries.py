"""
Layer 1 — Hard Boundaries.

Universal, zero-config protection. Ships with ARM. No user configuration.
No CapabilityToken override. These are architectural invariants.

Five boundaries enforced:
  HB-1: No string argument > 10,000 characters (bulk exfiltration payload)
  HB-2: No sensitive file reads (SSH keys, AWS creds, .env, etc.)
  HB-3: No tool called > 100 times per session (runaway loop protection)
  HB-4: No credential patterns in string arguments (deterministic secret detection)
  HB-5: Schema pinning — tool schema changes after first call require re-auth (rug-pull)

Design: no ALLOW verdict — the layer returns PASS for everything that passes.
Only DENY is definitive. This lets downstream layers add further constraints
without Hard Boundaries claiming ownership of legitimate calls.

Thread safety: HardBoundariesLayer maintains per-session call counts and schema
hashes. It is NOT thread-safe. Use one engine instance per thread, or synchronize
externally.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from typing import Any

from arm_core.layers.base import EvaluationContext, LayerResult, LayerVerdict, PolicyLayer

# HB-2: Filesystem paths that are always blocked regardless of tool
SENSITIVE_PATH_PATTERNS: tuple[str, ...] = (
    "~/.ssh/*",
    "~/.aws/*",
    "~/.cursor/*",
    "~/.config/*/credentials*",
    "*/.env",
    "*/secrets.*",
    "*/id_rsa*",
    "*/id_ed25519*",
    "*/.netrc",
    "*/token*secret*",
)

# Filesystem parameter names — args likely to carry file paths
FILESYSTEM_ARG_NAMES: frozenset[str] = frozenset(
    {
        "path", "file", "filepath", "file_path", "filename", "file_name",
        "directory", "dir", "folder", "src", "dst", "source", "destination",
        "target", "location",
    }
)

# HB-4: Credential patterns that must never appear in tool arguments.
# All patterns use leading/trailing wildcards so they match even when
# the credential is embedded in the middle of a longer string.
CREDENTIAL_PATTERNS: tuple[str, ...] = (
    "*BEGIN*PRIVATE*KEY*",
    "*BEGIN*RSA*",
    "*BEGIN*CERTIFICATE*",
    "*BEGIN*OPENSSH*",
    "*aws_access_key*",
    "*aws_secret*",
    "*AKIA*",              # AWS access key ID prefix
    "*eyJhbG*",            # JWT header (base64 for {"alg")
    "*ghp_*",              # GitHub personal access token
    "*ghs_*",              # GitHub app token
    "*sk_live_*",          # Stripe live secret key
    "*sk_test_*",          # Stripe test secret key
    "*xoxb-*",             # Slack bot token
    "*xoxp-*",             # Slack user token
    "*-----BEGIN*",        # Any PEM block
)

# HB-3: Per-session call limit per tool
HARD_CALL_LIMIT = 100


class HardBoundariesLayer(PolicyLayer):
    """
    Layer 1: Hard Boundaries.

    State: call counters per session (keyed by session_id+tool_name)
    and schema hashes for rug-pull detection.
    """

    def __init__(self) -> None:
        # {session_id: {tool_name: count}}
        self._call_counts: dict[str, dict[str, int]] = {}
        # {session_id: {tool_name: schema_hash}}
        self._schema_hashes: dict[str, dict[str, str]] = {}

    @property
    def name(self) -> str:
        return "hard_boundaries"

    @property
    def order(self) -> int:
        return 100

    def evaluate(
        self, tool_name: str, args: dict[str, Any], context: EvaluationContext
    ) -> LayerResult:
        session = context.session_id

        # HB-5: Schema pinning (check before anything else)
        if context.tool_schemas and tool_name in context.tool_schemas:
            schema_result = self._check_schema_pin(tool_name, context)
            if schema_result is not None:
                return schema_result

        # HB-3: Call budget
        counts = self._call_counts.setdefault(session, {})
        current = counts.get(tool_name, 0)
        if current >= HARD_CALL_LIMIT:
            return LayerResult(
                verdict=LayerVerdict.DENY,
                layer_name=self.name,
                reason=(
                    f"HB-3: Tool '{tool_name}' exceeded hard call limit "
                    f"({current}/{HARD_CALL_LIMIT} calls this session)"
                ),
                tool_name=tool_name,
                args=args,
            )

        # HB-1, HB-2, HB-4: Argument-level checks
        for arg_name, arg_value in args.items():
            if arg_value is None:
                continue
            arg_str = str(arg_value)

            # HB-1: Argument length
            if len(arg_str) > 10_000:
                return LayerResult(
                    verdict=LayerVerdict.DENY,
                    layer_name=self.name,
                    reason=(
                        f"HB-1: Argument '{arg_name}' exceeds 10,000-char hard limit "
                        f"({len(arg_str)} chars) — likely bulk exfiltration payload"
                    ),
                    tool_name=tool_name,
                    args=args,
                )

            # HB-2: Sensitive file paths (only for filesystem-named args)
            if arg_name.lower() in FILESYSTEM_ARG_NAMES:
                for pattern in SENSITIVE_PATH_PATTERNS:
                    if fnmatch.fnmatch(arg_str, pattern) or fnmatch.fnmatch(
                        arg_str.replace("\\", "/"), pattern
                    ):
                        return LayerResult(
                            verdict=LayerVerdict.DENY,
                            layer_name=self.name,
                            reason=(
                                f"HB-2: Argument '{arg_name}' matches sensitive path "
                                f"pattern '{pattern}' — protected file access blocked"
                            ),
                            tool_name=tool_name,
                            args=args,
                        )

            # HB-4: Credential patterns in any string argument
            for pattern in CREDENTIAL_PATTERNS:
                if fnmatch.fnmatch(arg_str, pattern) or fnmatch.fnmatch(
                    arg_str.upper(), pattern.upper()
                ):
                    return LayerResult(
                        verdict=LayerVerdict.DENY,
                        layer_name=self.name,
                        reason=(
                            f"HB-4: Argument '{arg_name}' matches credential pattern "
                            f"'{pattern}' — potential secret exfiltration blocked"
                        ),
                        tool_name=tool_name,
                        args=args,
                    )

        # All checks passed — increment counter, return PASS (not ALLOW)
        counts[tool_name] = current + 1
        return LayerResult(
            verdict=LayerVerdict.PASS,
            layer_name=self.name,
            reason="Hard boundaries passed",
            tool_name=tool_name,
            args=args,
        )

    def _check_schema_pin(
        self, tool_name: str, context: EvaluationContext
    ) -> LayerResult | None:
        """
        HB-5: Schema pinning. Hash the current schema and compare to stored hash.
        First call stores the hash. Subsequent calls verify it.
        Returns a DENY LayerResult if schema changed, None if OK.
        """
        session = context.session_id
        schema = context.tool_schemas[tool_name]  # type: ignore[index]
        current_hash = hashlib.sha256(
            json.dumps(schema, sort_keys=True).encode()
        ).hexdigest()

        hashes = self._schema_hashes.setdefault(session, {})
        if tool_name not in hashes:
            # First call — pin the schema
            hashes[tool_name] = current_hash
            return None

        if hashes[tool_name] != current_hash:
            return LayerResult(
                verdict=LayerVerdict.DENY,
                layer_name=self.name,
                reason=(
                    f"HB-5: Tool '{tool_name}' schema changed after initial approval "
                    f"(stored={hashes[tool_name][:12]}… current={current_hash[:12]}…) "
                    f"— possible rug-pull attack"
                ),
                tool_name=tool_name,
                args={},
            )
        return None
