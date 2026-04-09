"""
Layer 3 — Schema-Derived Constraints.

Auto-generates constraints from MCP tool inputSchema at evaluation time.
Zero user input — the schema IS the policy source.

Auto-generation rules:
  SD-1: String params with suspicious names (sidenote, note, metadata, etc.)
        → max_length: 100 + credential pattern blocking
  SD-2: String params with filesystem names (path, file, dir, etc.)
        → sensitive path blocking (same as HB-2, but catches tools HB didn't see)
  SD-3: Optional string params (not in 'required' list)
        → max_length: 50 (optional params are the #1 exfiltration channel)
  SD-4: Network params (url, endpoint, host) → logged for audit trail (enforcement planned)

The thesis: the attacker adds 'sidenote' to add(a, b) to create an exfil channel.
The tool schema reveals this param is optional and has a suspicious name.
SD-1 + SD-3 auto-apply tight limits without the user ever writing a rule.
"""

from __future__ import annotations

import fnmatch
from typing import Any

from arm_core.layers.base import EvaluationContext, LayerResult, LayerVerdict, PolicyLayer
from arm_core.layers.hard_boundaries import (
    CREDENTIAL_PATTERNS,
    SENSITIVE_PATH_PATTERNS,
)

# SD-1: Parameter names that signal side-channel / exfiltration risk
SUSPICIOUS_STRING_PARAMS: frozenset[str] = frozenset(
    {
        "sidenote", "note", "notes", "context", "metadata", "comment",
        "description", "memo", "annotation", "log", "message", "info",
        "extra", "additional", "supplementary", "auxiliary", "remark",
        "observation", "detail", "summary", "history", "conversation",
        "text", "body", "payload", "data", "content", "hint", "tag",
        "label", "reason", "rationale", "explanation",
    }
)

# Filesystem parameter names (same as HB layer, re-applied at schema level)
FILESYSTEM_ARG_NAMES: frozenset[str] = frozenset(
    {
        "path", "file", "filepath", "file_path", "filename", "file_name",
        "directory", "dir", "folder", "src", "dst", "source", "destination",
        "target", "location",
    }
)

# SD-4: Network parameter names (flagged but not yet enforced)
NETWORK_ARG_NAMES: frozenset[str] = frozenset(
    {
        "url", "endpoint", "uri", "href", "link", "host", "domain",
        "server", "address", "ip", "addr",
    }
)

# Max lengths applied by schema-derived rules
MAX_LEN_SUSPICIOUS = 100   # SD-1: suspicious params
MAX_LEN_OPTIONAL = 50      # SD-3: any optional string param


class SchemaDerivedLayer(PolicyLayer):
    """
    Layer 3: Schema-Derived Constraints.

    Reads tool inputSchema from context.tool_schemas and derives constraints.
    If no schema is available for a tool, returns PASS (no opinion).
    """

    @property
    def name(self) -> str:
        return "schema_derived"

    @property
    def order(self) -> int:
        return 300

    def evaluate(
        self, tool_name: str, args: dict[str, Any], context: EvaluationContext
    ) -> LayerResult:
        if not context.tool_schemas or tool_name not in context.tool_schemas:
            return LayerResult(
                verdict=LayerVerdict.PASS,
                layer_name=self.name,
                reason="No schema available — no schema-derived constraints applied",
                tool_name=tool_name,
                args=args,
            )

        schema = context.tool_schemas[tool_name]
        properties: dict[str, dict] = schema.get("properties", {})
        required: set[str] = set(schema.get("required", []))

        for arg_name, arg_value in args.items():
            if arg_value is None:
                continue

            arg_str = str(arg_value)
            param_schema = properties.get(arg_name, {})
            param_type = param_schema.get("type", "")
            param_name_lower = arg_name.lower()
            is_optional = arg_name not in required

            # Only check string params
            if param_type not in ("string", "") and not isinstance(arg_value, str):
                continue

            # SD-1: Suspicious parameter name
            if param_name_lower in SUSPICIOUS_STRING_PARAMS:
                if len(arg_str) > MAX_LEN_SUSPICIOUS:
                    return LayerResult(
                        verdict=LayerVerdict.DENY,
                        layer_name=self.name,
                        reason=(
                            f"SD-1: Argument '{arg_name}' is a suspicious side-channel param "
                            f"and exceeds auto-derived max length "
                            f"({len(arg_str)} > {MAX_LEN_SUSPICIOUS})"
                        ),
                        tool_name=tool_name,
                        args=args,
                    )
                # Also block credentials in suspicious params
                for pattern in CREDENTIAL_PATTERNS:
                    if fnmatch.fnmatch(arg_str, pattern) or fnmatch.fnmatch(
                        arg_str.upper(), pattern.upper()
                    ):
                        return LayerResult(
                            verdict=LayerVerdict.DENY,
                            layer_name=self.name,
                            reason=(
                                f"SD-1: Credential pattern '{pattern}' detected "
                                f"in suspicious param '{arg_name}'"
                            ),
                            tool_name=tool_name,
                            args=args,
                        )

            # SD-2: Filesystem parameter name → sensitive path blocking
            if param_name_lower in FILESYSTEM_ARG_NAMES:
                for pattern in SENSITIVE_PATH_PATTERNS:
                    if fnmatch.fnmatch(arg_str, pattern) or fnmatch.fnmatch(
                        arg_str.replace("\\", "/"), pattern
                    ):
                        return LayerResult(
                            verdict=LayerVerdict.DENY,
                            layer_name=self.name,
                            reason=(
                                f"SD-2: Filesystem param '{arg_name}' targets sensitive "
                                f"path pattern '{pattern}'"
                            ),
                            tool_name=tool_name,
                            args=args,
                        )

            # SD-3: Optional string params — tight length limit
            if (
                is_optional
                and param_name_lower not in FILESYSTEM_ARG_NAMES
                and param_name_lower not in SUSPICIOUS_STRING_PARAMS
                and isinstance(arg_value, str)
                and len(arg_str) > MAX_LEN_OPTIONAL
            ):
                return LayerResult(
                    verdict=LayerVerdict.DENY,
                    layer_name=self.name,
                    reason=(
                        f"SD-3: Optional string param '{arg_name}' exceeds "
                        f"auto-derived limit for optional params "
                        f"({len(arg_str)} > {MAX_LEN_OPTIONAL})"
                    ),
                    tool_name=tool_name,
                    args=args,
                )

            # SD-4: Network params — logged for audit trail; domain
            # allowlisting is a planned extension (not yet enforced).
            if param_name_lower in NETWORK_ARG_NAMES:
                pass

        return LayerResult(
            verdict=LayerVerdict.PASS,
            layer_name=self.name,
            reason="Schema-derived constraints passed",
            tool_name=tool_name,
            args=args,
        )
