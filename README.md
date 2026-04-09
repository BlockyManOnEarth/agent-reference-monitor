# Agent Reference Monitor (ARM)

Provenance-aware runtime security for tool-calling LLM agents. Tracks data flows, denied actions, and causal influence across agent sessions. Blocks attacks that every stateless enforcer misses.

**Paper:** [Causality Laundering: Denial-Feedback Leakage in Tool-Calling LLM Agents](https://arxiv.org/abs/2604.04035)

## Install

```bash
pip install agent-reference-monitor
```

With optional dependencies:

```bash
pip install agent-reference-monitor[all]    # LLM clients + MCP + dotenv
pip install agent-reference-monitor[llm]    # anthropic + openai clients only
pip install agent-reference-monitor[mcp]    # MCP protocol support
```

## Quickstart

```python
from arm_provenance import GraphAwareEngine, TrustLevel

# Create an engine with default security layers (zero config)
engine = GraphAwareEngine()

# Every tool call goes through ARM before execution
decision = engine.evaluate_tool_call(
    tool_name="send_email",
    arguments={"to": "external@corp.com", "body": "Q3 layoff list attached"},
    context={"session_id": "agent-001"},
)

if decision.decision.value == "deny":
    print(f"Blocked: {decision.reason}")
```

ARM sits between the LLM and the tools. It does not modify your agent framework, rewrite your tools, or add LLM calls. It wraps existing infrastructure.

## What ARM Catches That Others Miss

We ran the same attack through 4 real, pip-installed agent security engines:

```
Microsoft Agent Governance Toolkit  → ALLOW
EnforceCore                         → ALLOW
TheAIOS Guardrails                  → ALLOW
ARM                                 → BLOCK
```

**The attack:** An employee asks an AI assistant to check which shared directories they can access. 3 are denied. The denials reveal material non-public information (layoffs planned, M&A activity). The employee asks to email the summary.

Every stateless enforcer allows the email because each call is individually authorized. Their policy model (per-call allow/deny) has no mechanism to correlate denials across calls. The attack is in the sequence, not in any single call.

ARM blocks it because it tracks denied actions as provenance events. Counterfactual edges connect the denials to the exfiltration attempt. 3 chains, 1 block.

This attack class is called **causality laundering**: information leaked through the structure of denials, not through data content. No existing package tracks denied actions as provenance events. We surveyed 20+. The gap is confirmed.

**Run the demo yourself:**

```bash
git clone https://github.com/BlockyManOnEarth/agent-reference-monitor
cd agent-reference-monitor
pip install -e ".[all]"
pip install agent-os-kernel enforcecore theaios-guardrails

python demos/head-to-head.py
```

## How It Works

ARM maintains a **provenance graph** (a causal DAG) that tracks every data flow, tool call, and denial across an agent session. When a tool call arrives, ARM does not just check "is this call authorized right now?" It checks "was this call causally influenced by a denied action?"

### Layer Architecture

```
Layer 1: Hard Boundaries (zero config, always on)
  No string arg > 10,000 chars. No sensitive file reads.
  No credential patterns. Schema pinning (rug-pull detection).

Layer 2: Graph Provenance (zero config, uses session history)
  For each argument: does this value trace back to a user message
  or an allowed tool output in the provenance graph?
  If not → DENY.

Layer 3: Schema-Derived Constraints (zero config)
  Suspicious param names (sidenote, note, metadata) → max 100 chars.
  Filesystem params → sensitive path blocking.

Layer 4: Privileged Action Policy
  Actions like send_email, write_file, execute_code require all
  input data to have TRUSTED or higher provenance. Blocks
  exfiltration of information derived from denied actions.

Layer 5: Manual Policy (optional, operator-written)
  Explicit CapabilityToken rules: blocked_patterns, allowed_values,
  max_calls, max_length.
```

Anderson's three reference monitor properties:
- **Complete mediation**: every tool call passes through the pipeline before execution
- **Tamper-proof**: deterministic Python, no LLM in the enforcement path
- **Verifiable**: small codebase (~1,900 lines), each layer independently testable

### Provenance Graph

ARM's provenance graph tracks:
- **Data nodes**: user messages, tool results, tool arguments (with field-level trust)
- **Action nodes**: tool calls (allowed and denied)
- **Denied action nodes**: tool calls that were blocked, with the denial reason
- **Edges**: data flow (DERIVED_FROM), tool I/O (INPUT_TO, OUTPUT_OF), and counterfactual influence (COUNTERFACTUAL)

When a tool call is denied and a subsequent call uses related information, ARM creates a counterfactual edge. This is the mechanism that catches causality laundering: the denied action's existence influenced the agent's behavior, even though no data was explicitly passed.

## Attack Demonstrations

### 1. MCP Tool Poisoning (file exfiltration)

GPT-4o-mini reads `~/.ssh/id_rsa` and exfiltrates 238 characters of credentials via a math tool's `sidenote` parameter. Returns "3 + 5 = 8" to the user.

ARM blocks at capability token check: `read_file` is not in scope.

```bash
python attacks/01-mcp-tool-poisoning/simulate_attack.py     # deterministic
python attacks/01-mcp-tool-poisoning/test_with_llm.py       # requires ANTHROPIC_API_KEY
python attacks/01-mcp-tool-poisoning/test_with_openai.py    # requires OPENAI_API_KEY
```

### 2. Context Window Exfiltration (novel attack class)

No `read_file` needed. A multi-server session places sensitive data in the LLM's context window via trusted tool results. A poisoned server instructs the LLM to dump the context window through a tool argument. 1,301 characters exfiltrated without ARM. 0 with ARM.

```bash
python attacks/02-context-window-exfiltration/simulate_attack.py
```

### 3. Layered Comparison (9 test cases x 5 configurations)

The central finding. 9 attack scenarios across 5 defense configurations. Layer 1 alone misses slow-exfiltration variants (35 characters, no credential pattern, passes every static rule). Layer 2 catches them because the data has no provenance in the session.

```bash
python attacks/03-layered-comparison/compare_layers.py
```

### 4. Causality Laundering (head-to-head vs. competitors)

```bash
python demos/causality-laundering.py    # standalone walkthrough
python demos/head-to-head.py            # ARM vs. 3 real competitors
```

## Key Results

| Scenario | Without ARM | With ARM |
|----------|-------------|----------|
| MCP tool poisoning (credential exfil) | 238 chars exfiltrated | 0 chars, DENY at capability check |
| Context window exfiltration | 1,301 chars exfiltrated | 0 chars, 4 DENY decisions |
| Slow exfil (35 chars, no pattern match) | ALLOW by every static rule | DENY at provenance layer |
| Causality laundering (3 denied dirs) | ALLOW by 3 competing engines | DENY, 3 counterfactual chains |

## Project Structure

```
arm_core/                        Core enforcement library
  layers/                        5-layer pipeline (hard boundaries, provenance,
                                 schema-derived, privileged action, manual policy)
  capability_token.py            Session-scoped capability tokens
  policy_engine.py               LayeredPolicyEngine
  audit_log.py                   Hash-chained tamper-evident audit log
  mcp_wrapper.py                 MCP proxy server with ARM enforcement

arm_provenance/                  Causal provenance graph and graph-backed enforcement
  provenance_graph.py            ProvenanceGraph (rustworkx DAG)
  graph_provenance_layer.py      Graph-based L2 replacement
  graph_aware_engine.py          Integrated engine (the main entry point)
  privileged_action_layer.py     L4: privileged action enforcement

attacks/                         Attack reproductions with before/after evidence
  01-mcp-tool-poisoning/         File exfiltration via poisoned tool description
  02-context-window-exfiltration/ Context dump via multi-server session
  03-layered-comparison/         9 x 5 comparative simulation

demos/                           Standalone demonstrations
  head-to-head.py                ARM vs. 3 real competitors (70ms, zero cost)
  causality-laundering.py        Causality laundering walkthrough
  side-by-side.py                Visual comparison

benchmarks/                      AgentDojo benchmark adapter
  agentdojo_adapter.py           Native BasePipelineElement subclass
  run_benchmark.py               Benchmark runner

tests/                           Test suite (57+ tests)
```

## Comparison with Existing Tools

ARM is complementary to existing defenses, not competitive. Stateless enforcers answer "is this call authorized right now?" ARM answers "was this call causally influenced by a denied action?" A production stack benefits from both.

| Capability | Microsoft AGT | EnforceCore | TheAIOS | ARM |
|------------|--------------|-------------|---------|-----|
| Per-call policy enforcement | Yes | Yes | Yes | Yes |
| Denied action tracking | No | No | No | **Yes** |
| Cross-call causal reasoning | No | No | No | **Yes** |
| Counterfactual chain detection | No | No | No | **Yes** |
| Provenance graph | No | No | No | **Yes** |
| Zero additional LLM calls | Yes | Yes | Yes | Yes |

## Related Work

- Anderson (1972): reference monitor properties (complete mediation, tamper-proof, verifiable)
- Green, Karvounarakis, Tannen (2007): provenance semirings
- Necula (1997): proof-carrying code (LLM as untrusted code producer, ARM as verifier)
- FIDES (Microsoft, 2025): flat taint labels, no graph, no causality tracking
- CaMeL (Google DeepMind, 2025): dual-LLM isolation, requires custom interpreter runtime
- AgentDojo (ETH Zurich / Invariant Labs): benchmark for agent defenses against prompt injection

## Limitations

- **Single-threaded.** ARM is designed for sequential tool-call pipelines (one call at a time per session). It is not thread-safe. Use one engine instance per thread or synchronize externally.
- **Syntactic provenance linking.** L2G traces data flows via substring matching on tool outputs and arguments. If an LLM reformats data (e.g., paraphrases, changes case), the syntactic link is lost. L2.5 (privileged-action policy) compensates for this in prompt injection scenarios by conservatively blocking side-effecting tools when untrusted data is in the session.
- **L2.5 is conservative.** The privileged-action policy blocks all side-effecting tools when any untrusted data exists in the session graph. This prevents prompt injection but can block legitimate actions after reading external data (e.g., "read my emails then send a reply"). A taint-window mechanism (close on new user message) is planned.

## Security

To report a vulnerability, please email mohammadh.chinaei@gmail.com. Do not open a public issue.

## Author

Mohammad Hossein Chinaei, PhD
Senior AI Engineer | Independent Researcher in Agentic Systems Security

- Paper: [arxiv.org/abs/2604.04035](https://arxiv.org/abs/2604.04035)
- GitHub: [github.com/BlockyManOnEarth](https://github.com/BlockyManOnEarth)

## License

MIT
