#!/usr/bin/env bash
# Gemma 4 E4B: workspace suite, nodefense + ARM only (no flat).
# Flat is an internal ablation; the only comparison that matters is undefended vs ARM.
# Resumes from saved results (no --force-rerun).

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "=== [$(date)] Starting Gemma 4 E4B workspace benchmark ==="

echo ""
echo "=== [$(date)] Run 1/2: nodefense ==="
python -m benchmarks.run_benchmark \
  --model gemma-4-e4b \
  --suite workspace \
  --defense nodefense \
  --attack important_instructions \
  --logdir runs/gemma4_e4b_workspace_nodefense

echo ""
echo "=== [$(date)] Run 2/2: arm ==="
python -m benchmarks.run_benchmark \
  --model gemma-4-e4b \
  --suite workspace \
  --defense arm \
  --attack important_instructions \
  --logdir runs/gemma4_e4b_workspace_arm

echo ""
echo "=== [$(date)] Both runs complete! ==="
echo "Results:"
for d in workspace_nodefense workspace_arm; do
  echo "  runs/gemma4_e4b_$d/summary.json"
done
