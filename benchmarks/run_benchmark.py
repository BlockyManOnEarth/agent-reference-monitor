#!/usr/bin/env python3
"""
Run ARM evaluation on AgentDojo benchmark.

Usage:
    # Single suite, single model, ARM defense
    python -m benchmarks.run_benchmark \
        --suite workspace \
        --model gpt-4o-2024-05-13 \
        --defense arm \
        --attack important_instructions

    # All suites, compare ARM vs flat vs no-defense
    python -m benchmarks.run_benchmark \
        --suite all \
        --model gpt-4o-2024-05-13 \
        --defense all \
        --attack important_instructions

    # Quick smoke test (1 user task, 1 injection task)
    python -m benchmarks.run_benchmark \
        --suite workspace \
        --model gpt-4o-2024-05-13 \
        --defense arm \
        --attack important_instructions \
        --user-tasks user_task_0 \
        --injection-tasks injection_task_0
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from agentdojo.benchmark import (
    SuiteResults,
    aggregate_results,
    benchmark_suite_with_injections,
    benchmark_suite_without_injections,
)
from agentdojo.task_suite.load_suites import get_suites

from benchmarks.agentdojo_adapter import (
    build_arm_pipeline,
    build_flat_pipeline,
    build_nodefense_pipeline,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

ALL_SUITES = ["workspace", "slack", "travel_agency", "banking"]
ALL_DEFENSES = ["arm", "flat", "nodefense"]

# Map model IDs not in AgentDojo's registry to a known model ID string
# so the important_instructions attack can resolve the model name.
# The attack uses the pipeline name to find the model; we embed a known
# model ID in the pipeline name so it resolves correctly.
_MODEL_ALIAS = {
    "claude-sonnet-4-20250514": "claude-3-5-sonnet-20241022",
    "claude-opus-4-20250514": "claude-3-opus-20240229",
    "claude-haiku-4-5-20251001": "claude-3-haiku-20240307",
    "gemma-4-e4b": "gpt-4o-2024-05-13",
    "gemma-4-e2b": "gpt-4o-2024-05-13",
    "gemma-4-12b": "gpt-4o-2024-05-13",
    "gemma-4-27b": "gpt-4o-2024-05-13",
}


def get_llm(model: str):
    """Create an LLM pipeline element from a model name."""
    # Handle models not registered in AgentDojo's enum
    if model.startswith("claude-sonnet-4") or model.startswith("claude-opus-4") or model.startswith("claude-haiku-4"):
        import anthropic
        from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM
        client = anthropic.Anthropic()
        return AnthropicLLM(client, model)

    if model.startswith("gemma-4") or model.startswith("ollama/"):
        import os

        from openai import OpenAI
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM

        base_url = os.environ.get("OPENAI_BASE_URL", "http://localhost:11434/v1")
        client = OpenAI(base_url=base_url, api_key="ollama")

        model_map = {
            "gemma-4-e4b": "gemma4:e4b",
            "gemma-4-e2b": "gemma4:e2b",
            "gemma-4-12b": "gemma4:12b",
            "gemma-4-27b": "gemma4:27b",
        }
        ollama_model = model_map.get(model, model)
        return OpenAILLM(client, ollama_model)

    from agentdojo.agent_pipeline.agent_pipeline import get_llm as agentdojo_get_llm
    from agentdojo.models import MODEL_PROVIDERS, ModelsEnum

    provider = MODEL_PROVIDERS[ModelsEnum(model)]
    return agentdojo_get_llm(provider, model, model_id=None, tool_delimiter="tool")


def get_attack(attack_name: str, task_suite, target_pipeline):
    """Load an attack by name from the AgentDojo registry."""
    from agentdojo.attacks.attack_registry import ATTACKS, load_attack

    # Force registration of built-in attacks
    import agentdojo.attacks.baseline_attacks  # noqa: F401
    import agentdojo.attacks.important_instructions_attacks  # noqa: F401

    return load_attack(attack_name, task_suite, target_pipeline)


def print_results(defense_name: str, suite_name: str, results: SuiteResults) -> dict:
    """Print and return aggregated results.

    AgentDojo semantics:
    - security_results[key] = True means the injection SUCCEEDED (bad)
    - security_results[key] = False means the injection FAILED (good, defended)
    So ASR = sum(security.values()) / len(security)
    """
    utility = results["utility_results"]
    security = results["security_results"]

    n_utility = len(utility)
    n_attacks_succeeded = sum(security.values())
    n_attacks_blocked = len(security) - n_attacks_succeeded
    n_utility_pass = sum(utility.values())

    asr = n_attacks_succeeded / len(security) if security else 0.0
    tcr = n_utility_pass / n_utility if n_utility else 0.0

    summary = {
        "defense": defense_name,
        "suite": suite_name,
        "total_scenarios": len(security),
        "attacks_succeeded": n_attacks_succeeded,
        "attacks_blocked": n_attacks_blocked,
        "attack_success_rate": round(asr, 4),
        "task_completion_rate": round(tcr, 4),
        "utility_pass": n_utility_pass,
        "utility_total": n_utility,
    }

    logger.info(
        f"[{defense_name}] {suite_name}: "
        f"ASR={asr:.1%}, TCR={tcr:.1%} "
        f"({n_attacks_blocked}/{len(security)} blocked, "
        f"{n_utility_pass}/{n_utility} utility)"
    )
    return summary


def run_benchmark(
    model: str,
    suite_names: list[str],
    defense_names: list[str],
    attack_name: str,
    logdir: Path,
    force_rerun: bool = False,
    user_tasks: list[str] | None = None,
    injection_tasks: list[str] | None = None,
) -> list[dict]:
    """Run the benchmark for all combinations of suite x defense."""
    from agentdojo.logging import OutputLogger

    llm = get_llm(model)
    all_results = []

    suites = get_suites("v1.2.2")

    # Initialize AgentDojo's logger with logdir so TraceLogger can find it
    agentdojo_logger = OutputLogger(logdir=str(logdir))

    with agentdojo_logger:
        for suite_name in suite_names:
            suite = suites[suite_name]
            logger.info(f"Suite: {suite_name} ({len(suite.user_tasks)} user tasks, {len(suite.injection_tasks)} injection tasks)")

            for defense_name in defense_names:
                logger.info(f"  Defense: {defense_name}")

                # Use aliased model name in pipeline name so AgentDojo's
                # attack can resolve the model (e.g., "Claude" for injection text)
                name_model = _MODEL_ALIAS.get(model, model)

                if defense_name == "arm":
                    pipeline = build_arm_pipeline(llm, name=f"arm-{name_model}")
                elif defense_name == "flat":
                    pipeline = build_flat_pipeline(llm, name=f"flat-{name_model}")
                elif defense_name == "nodefense":
                    pipeline = build_nodefense_pipeline(llm, name=f"nodefense-{name_model}")
                else:
                    raise ValueError(f"Unknown defense: {defense_name}")

                attack = get_attack(attack_name, suite, pipeline)

                # Run with injections (security evaluation)
                results = benchmark_suite_with_injections(
                    agent_pipeline=pipeline,
                    suite=suite,
                    attack=attack,
                    logdir=logdir,
                    force_rerun=force_rerun,
                    user_tasks=user_tasks,
                    injection_tasks=injection_tasks,
                )

                summary = print_results(defense_name, suite_name, results)
                summary["model"] = model
                summary["attack"] = attack_name
                all_results.append(summary)

    return all_results


def main():
    parser = argparse.ArgumentParser(description="Run ARM evaluation on AgentDojo")
    parser.add_argument(
        "--model", required=True,
        help="Model name (e.g., gpt-4o-2024-05-13, claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--suite", default="workspace",
        help="Suite name or 'all' for all suites",
    )
    parser.add_argument(
        "--defense", default="arm",
        help="Defense: arm, flat, nodefense, or 'all'",
    )
    parser.add_argument(
        "--attack", default="important_instructions",
        help="Attack name (default: important_instructions)",
    )
    parser.add_argument(
        "--logdir", default="runs/",
        help="Directory for benchmark logs (default: runs/)",
    )
    parser.add_argument(
        "--force-rerun", action="store_true",
        help="Force rerun even if logs exist",
    )
    parser.add_argument(
        "--user-tasks", nargs="*",
        help="Specific user tasks to run (for quick testing)",
    )
    parser.add_argument(
        "--injection-tasks", nargs="*",
        help="Specific injection tasks to run (for quick testing)",
    )

    args = parser.parse_args()

    suite_names = ALL_SUITES if args.suite == "all" else [args.suite]
    defense_names = ALL_DEFENSES if args.defense == "all" else [args.defense]

    results = run_benchmark(
        model=args.model,
        suite_names=suite_names,
        defense_names=defense_names,
        attack_name=args.attack,
        logdir=Path(args.logdir),
        force_rerun=args.force_rerun,
        user_tasks=args.user_tasks,
        injection_tasks=args.injection_tasks,
    )

    # Save aggregated results
    outpath = Path(args.logdir) / "summary.json"
    outpath.parent.mkdir(parents=True, exist_ok=True)
    with outpath.open("w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"Summary saved to {outpath}")


if __name__ == "__main__":
    main()
