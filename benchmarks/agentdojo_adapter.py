"""
ARM adapter for AgentDojo benchmark.

Provides ARMToolsExecutor, a BasePipelineElement that wraps AgentDojo's
ToolsExecutor with ARM's enforcement layer. Before each tool call, ARM's
GraphAwareEngine evaluates the call. On DENY, the tool is not executed and
an error message is returned to the LLM. On ALLOW, the tool executes and
the result is recorded in the provenance graph.

This is the first defense to natively subclass BasePipelineElement; all
prior defenses (FIDES, RTBAS, AgentArmor, CausalArmor) operate as
external wrappers or full pipeline replacements.
"""

from __future__ import annotations

import uuid
from ast import literal_eval
from collections.abc import Callable, Sequence
from typing import Any

import yaml
from pydantic import BaseModel

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionReturnType, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)

from arm_core.layers.base import EvaluationContext
from arm_provenance.graph_aware_engine import GraphAwareEngine
from arm_provenance.privileged_action_layer import DEFAULT_PRIVILEGED_ACTION_TOOLS
from arm_provenance.provenance_graph import TrustLevel


# Tools whose output contains external/user-provided data that could carry
# prompt injection payloads. Results from these tools are marked as
# TOOL_OUTPUT_UNTRUSTED in the provenance graph, so that subsequent tool
# calls using this data are flagged by L2G (graph provenance).
#
# This is the AgentDojo equivalent of FIDES's integrity label assignment.
# Tools not in this set return system-controlled data (dates, metadata,
# confirmation messages) and are marked TOOL_OUTPUT_TRUSTED.
UNTRUSTED_DATA_TOOLS: frozenset[str] = frozenset({
    # workspace: email bodies, file contents, calendar descriptions
    "get_unread_emails", "get_received_emails", "get_sent_emails",
    "get_draft_emails", "search_emails",
    "search_calendar_events", "get_day_calendar_events",
    "get_file_by_id", "list_files", "search_files",
    "search_files_by_filename",
    # slack: messages from other users, web content
    "read_channel_messages", "read_inbox",
    "get_webpage",
    # travel: reviews and descriptions from external sources
    "get_rating_reviews_for_hotels", "get_rating_reviews_for_restaurants",
    "get_rating_reviews_for_car_rental",
    # banking: file contents
    "read_file",
    "get_most_recent_transactions",
})


def _is_string_list(s: str) -> bool:
    try:
        parsed = literal_eval(s)
        return isinstance(parsed, list)
    except (ValueError, SyntaxError):
        return False


def _tool_result_to_str(
    tool_result: FunctionReturnType,
    dump_fn: Callable[[dict | list[dict]], str] = yaml.safe_dump,
) -> str:
    """Format tool output for the LLM (mirrors AgentDojo's default)."""
    if isinstance(tool_result, BaseModel):
        return dump_fn(tool_result.model_dump()).strip()
    if isinstance(tool_result, list):
        items = []
        for item in tool_result:
            if type(item) in [str, int]:
                items.append(str(item))
            elif isinstance(item, BaseModel):
                items.append(item.model_dump())
            else:
                raise TypeError(f"Invalid item type: {type(item)}")
        return dump_fn(items).strip()
    return str(tool_result)


class ARMToolsExecutor(BasePipelineElement):
    """
    Drop-in replacement for AgentDojo's ToolsExecutor that enforces ARM
    policies on every tool call.

    For each tool call in the assistant's message:
    1. Run GraphAwareEngine.evaluate(tool_name, args)
    2. If DENY: return an error to the LLM (tool not executed)
    3. If ALLOW: execute via runtime.run_function(), then record the
       result in the provenance graph

    The engine is reset per benchmark task (create a new ARMToolsExecutor
    or call reset() between tasks).
    """

    def __init__(
        self,
        engine: GraphAwareEngine | None = None,
        min_required_trust: TrustLevel = TrustLevel.TOOL_OUTPUT_TRUSTED,
        privileged_tools: frozenset[str] | None = None,
        tool_output_formatter: Callable[[FunctionReturnType], str] = tool_result_to_str,
    ) -> None:
        self._privileged_tools = privileged_tools or DEFAULT_PRIVILEGED_ACTION_TOOLS
        self.engine = engine or GraphAwareEngine.default(
            min_required_trust=min_required_trust,
            privileged_tools=self._privileged_tools,
        )
        self.output_formatter = tool_output_formatter
        self._initialized = False
        # Maps tool result text to the data node ID in the provenance graph,
        # so we can create INPUT_TO edges when a subsequent tool call uses
        # data from a prior result.
        self._result_text_to_nid: dict[str, str] = {}
        # All data node IDs from untrusted sources (for provenance linking)
        self._untrusted_data_nids: list[str] = []

    def reset(self) -> None:
        """Reset engine state for a new benchmark task."""
        self.engine = GraphAwareEngine.default(
            min_required_trust=self.engine._min_required_trust,
            privileged_tools=self._privileged_tools,
        )
        self._initialized = False
        self._result_text_to_nid = {}
        self._untrusted_data_nids = []

    def _ensure_context(self, messages: Sequence[ChatMessage]) -> None:
        """Initialize EvaluationContext from the message history on first call."""
        if self._initialized:
            return

        user_messages = []
        for msg in messages:
            if msg["role"] == "user":
                content_blocks = msg.get("content", [])
                text = " ".join(
                    b["content"] for b in content_blocks
                    if b.get("type") == "text" and b.get("content")
                )
                if text:
                    user_messages.append({"role": "user", "content": text})

        ctx = EvaluationContext(
            session_id=f"agentdojo_{uuid.uuid4().hex[:8]}",
            agent_id="agentdojo_agent",
            user_messages=user_messages,
        )
        self.engine.set_context(ctx)
        self._initialized = True

    def _get_trust_for_tool(self, tool_name: str) -> TrustLevel:
        """Determine the trust level for a tool's output."""
        if tool_name in UNTRUSTED_DATA_TOOLS:
            return TrustLevel.TOOL_OUTPUT_UNTRUSTED
        return TrustLevel.TOOL_OUTPUT_TRUSTED

    def _find_input_data_ids(self, args: dict[str, Any]) -> list[str]:
        """Find provenance graph data node IDs that feed into these args.

        Checks if any argument value (or substring) matches text from a
        prior tool result. If so, returns the corresponding data node IDs
        so the engine can create INPUT_TO edges in the provenance graph.
        This is how L2G traces tainted data from untrusted tool outputs
        to subsequent tool calls.
        """
        input_ids = []
        for arg_value in args.values():
            arg_str = str(arg_value)
            for result_text, nid in self._result_text_to_nid.items():
                # Check if the arg contains data from a prior tool result
                if len(result_text) >= 3 and result_text in arg_str:
                    input_ids.append(nid)
                elif len(arg_str) >= 3 and arg_str in result_text:
                    input_ids.append(nid)
        # NOTE: We no longer fall back to linking ALL untrusted nodes when
        # no syntactic match is found. That caused ~78% false positive rate.
        # LLM-mediated semantic flows (prompt injection) are now caught by
        # PrivilegedActionLayer (L2.5), which blocks side-effecting tools
        # when untrusted data exists in the session. L2G handles syntactic
        # flows; L2.5 handles semantic flows. Together they cover both channels.
        return input_ids

    def _record_tool_result_in_graph(
        self,
        tool_name: str,
        result: FunctionReturnType,
        formatted_result: str,
    ) -> str | None:
        """Record a successful tool result in the provenance graph."""
        trust = self._get_trust_for_tool(tool_name)
        fields = None
        if isinstance(result, BaseModel):
            fields = result.model_dump()
        elif isinstance(result, dict):
            fields = result

        try:
            nid = self.engine.record_tool_result(
                call_id_prefix=tool_name,
                result=result,
                trust=trust,
                fields=fields,
            )
            if nid:
                # Store mapping from result text to node ID for provenance linking
                self._result_text_to_nid[formatted_result[:200]] = nid
                if trust == TrustLevel.TOOL_OUTPUT_UNTRUSTED:
                    self._untrusted_data_nids.append(nid)
            return nid
        except (KeyError, ValueError, TypeError) as exc:
            # Graph insertion can fail on malformed results or index collisions.
            # Fail open here (adapter layer, not enforcement) but log for debugging.
            import logging
            logging.getLogger("arm.adapter").warning("record_tool_result failed: %s", exc)
            return None

    def _update_context_history(
        self,
        tool_name: str,
        args: dict[str, Any],
        result: Any,
        decision: str,
    ) -> None:
        """Append to the engine's EvaluationContext.tool_call_history."""
        if self.engine._context is not None:
            self.engine._context.tool_call_history.append({
                "tool": tool_name,
                "args": args,
                "result": str(result)[:500],
                "decision": decision,
            })

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        if messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        self._ensure_context(messages)

        tool_call_results: list[ChatToolResultMessage] = []

        for tool_call in messages[-1]["tool_calls"]:
            # Skip empty function names (Google LLM quirk)
            if tool_call.function == EMPTY_FUNCTION_NAME:
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error="Empty function name provided.",
                    )
                )
                continue

            # Check tool exists in runtime
            if tool_call.function not in (t.name for t in runtime.functions.values()):
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=f"Invalid tool {tool_call.function} provided.",
                    )
                )
                continue

            # Convert string lists (AgentDojo convention)
            for arg_k, arg_v in tool_call.args.items():
                if isinstance(arg_v, str) and _is_string_list(arg_v):
                    tool_call.args[arg_k] = literal_eval(arg_v)

            # ---- ARM ENFORCEMENT ----
            # Find data provenance: which prior tool results feed into
            # this call's arguments?
            input_data_ids = self._find_input_data_ids(dict(tool_call.args))

            arm_decision = self.engine.evaluate(
                tool_name=tool_call.function,
                args=dict(tool_call.args),
                input_data_ids=input_data_ids if input_data_ids else None,
            )

            if arm_decision.denied:
                # Tool call blocked by ARM
                deny_msg = f"ARM policy denied this tool call: {arm_decision.reason}"
                self._update_context_history(
                    tool_call.function, dict(tool_call.args), None, "deny",
                )
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(deny_msg)],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=deny_msg,
                    )
                )
                continue

            # ---- TOOL EXECUTION (ARM allowed) ----
            tool_call_result, error = runtime.run_function(
                env, tool_call.function, tool_call.args,
            )

            formatted = self.output_formatter(tool_call_result)

            # Record result in provenance graph with trust level
            self._record_tool_result_in_graph(
                tool_name=tool_call.function,
                result=tool_call_result,
                formatted_result=formatted,
            )
            self._update_context_history(
                tool_call.function, dict(tool_call.args),
                tool_call_result, "allow",
            )
            tool_call_results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(formatted)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )

        return query, runtime, env, [*messages, *tool_call_results], extra_args


class FlatBaselineToolsExecutor(BasePipelineElement):
    """
    Flat baseline (L2 only, no graph) for comparison.

    Uses LayeredPolicyEngine with citation-based provenance (L2) instead
    of GraphAwareEngine (L2G). This is the "flat" configuration from
    the paper's evaluation: it checks whether argument values appear
    in tool-call history, but has no graph traversal, no counterfactual
    edges, and no field-level provenance.
    """

    def __init__(
        self,
        tool_output_formatter: Callable[[FunctionReturnType], str] = tool_result_to_str,
    ) -> None:
        from arm_core.policy_engine import LayeredPolicyEngine
        self._engine = LayeredPolicyEngine.default(simulation_mode=True)
        self.output_formatter = tool_output_formatter
        self._initialized = False

    def reset(self) -> None:
        from arm_core.policy_engine import LayeredPolicyEngine
        self._engine = LayeredPolicyEngine.default(simulation_mode=True)
        self._initialized = False

    def _ensure_context(self, messages: Sequence[ChatMessage]) -> None:
        if self._initialized:
            return
        user_messages = []
        for msg in messages:
            if msg["role"] == "user":
                content_blocks = msg.get("content", [])
                text = " ".join(
                    b["content"] for b in content_blocks
                    if b.get("type") == "text" and b.get("content")
                )
                if text:
                    user_messages.append({"role": "user", "content": text})
        ctx = EvaluationContext(
            session_id=f"flat_{uuid.uuid4().hex[:8]}",
            agent_id="agentdojo_agent",
            user_messages=user_messages,
        )
        self._engine.set_context(ctx)
        self._initialized = True

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        if messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        self._ensure_context(messages)

        # Update context with tool results from previous messages
        tool_history = []
        for msg in messages:
            if msg["role"] == "tool":
                tc = msg.get("tool_call")
                if tc:
                    content_blocks = msg.get("content", [])
                    result_text = " ".join(
                        b["content"] for b in content_blocks
                        if b.get("type") == "text" and b.get("content")
                    )
                    tool_history.append({
                        "tool": tc.function,
                        "args": dict(tc.args),
                        "result": result_text[:500],
                        "decision": "allow",
                    })
        if self._engine._context is not None:
            self._engine._context.tool_call_history = tool_history

        tool_call_results: list[ChatToolResultMessage] = []

        for tool_call in messages[-1]["tool_calls"]:
            if tool_call.function == EMPTY_FUNCTION_NAME:
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error="Empty function name provided.",
                    )
                )
                continue

            if tool_call.function not in (t.name for t in runtime.functions.values()):
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=f"Invalid tool {tool_call.function} provided.",
                    )
                )
                continue

            for arg_k, arg_v in tool_call.args.items():
                if isinstance(arg_v, str) and _is_string_list(arg_v):
                    tool_call.args[arg_k] = literal_eval(arg_v)

            decision = self._engine.evaluate(
                tool_name=tool_call.function,
                args=dict(tool_call.args),
            )

            if decision.denied:
                deny_msg = f"Flat baseline denied this tool call: {decision.reason}"
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(deny_msg)],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=deny_msg,
                    )
                )
                continue

            tool_call_result, error = runtime.run_function(
                env, tool_call.function, tool_call.args,
            )
            formatted = self.output_formatter(tool_call_result)
            tool_call_results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(formatted)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )

        return query, runtime, env, [*messages, *tool_call_results], extra_args


def build_arm_pipeline(
    llm: BasePipelineElement,
    system_message: str | None = None,
    min_required_trust: TrustLevel = TrustLevel.TOOL_OUTPUT_TRUSTED,
    name: str | None = None,
) -> BasePipelineElement:
    """
    Build an AgentDojo pipeline with ARM enforcement.

    The pipeline structure:
        SystemMessage -> InitQuery -> LLM -> ToolsExecutionLoop(
            ARMToolsExecutor -> LLM
        )
    """
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message

    if system_message is None:
        system_message = load_system_message(None)

    arm_executor = ARMToolsExecutor(min_required_trust=min_required_trust)
    tools_loop = ToolsExecutionLoop([arm_executor, llm])

    pipeline = AgentPipeline([
        SystemMessage(system_message),
        InitQuery(),
        llm,
        tools_loop,
    ])
    pipeline.name = name or f"arm-{getattr(llm, 'name', 'unknown')}"
    return pipeline


def build_flat_pipeline(
    llm: BasePipelineElement,
    system_message: str | None = None,
    name: str | None = None,
) -> BasePipelineElement:
    """Build an AgentDojo pipeline with flat baseline enforcement."""
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message

    if system_message is None:
        system_message = load_system_message(None)

    flat_executor = FlatBaselineToolsExecutor()
    tools_loop = ToolsExecutionLoop([flat_executor, llm])

    pipeline = AgentPipeline([
        SystemMessage(system_message),
        InitQuery(),
        llm,
        tools_loop,
    ])
    pipeline.name = name or f"flat-{getattr(llm, 'name', 'unknown')}"
    return pipeline


def build_nodefense_pipeline(
    llm: BasePipelineElement,
    system_message: str | None = None,
    name: str | None = None,
) -> BasePipelineElement:
    """Build a standard AgentDojo pipeline with no defense (baseline)."""
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor

    if system_message is None:
        system_message = load_system_message(None)

    tools_loop = ToolsExecutionLoop([ToolsExecutor(), llm])

    pipeline = AgentPipeline([
        SystemMessage(system_message),
        InitQuery(),
        llm,
        tools_loop,
    ])
    pipeline.name = name or f"nodefense-{getattr(llm, 'name', 'unknown')}"
    return pipeline
