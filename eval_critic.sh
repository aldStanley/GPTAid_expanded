#!/usr/bin/env bash
# eval_critic.sh — Run Stage 1+2 once, then fork Stage 3 with and without the
# Critic Agent on the SAME Stage 2 output, isolating the Critic's effect.
#
# Usage: ./eval_critic.sh [retrieval_depth] [max_rules_per_api]
#   retrieval_depth   default 1
#   max_rules_per_api default 5
#
# Output dirs:
#   results/critic_eval/            — Stage 1+2 output + Stage 3 without Critic
#   results/critic_eval_with_critic/ — Stage 3 with Critic (same Stage 2 input)
#
# After this completes, run:
#   python3 src/eval_critic_judge.py

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/config.json"

RETRIEVAL_DEPTH="${1:-1}"
MAX_RULES="${2:-5}"

SHARED_DIR="$SCRIPT_DIR/results/critic_eval"
CRITIC_DIR="$SCRIPT_DIR/results/critic_eval_with_critic"

# Save and restore config on exit
ORIG_CONFIG="$(cat "$CONFIG")"
restore_config() { echo "$ORIG_CONFIG" > "$CONFIG"; }
trap restore_config EXIT

write_config() {
    local critic="$1"
    local result_dir="$2"
    python3 - <<PYEOF
import json
cfg = {
    "retrieval_depth": $RETRIEVAL_DEPTH,
    "use_docker": True,
    "docker_image": "gptaid-sandbox",
    "critic_agent": $critic,
    "result_dir": "$result_dir",
    "max_rules_per_api": $MAX_RULES
}
with open("$CONFIG", "w") as f:
    json.dump(cfg, f, indent=4)
PYEOF
}

# ── Stage 1 + 2 (shared, no Critic) ───────────────────────────────────────────
echo ""
echo "========================================================"
echo "  Stage 1+2 (shared, retrieval_depth=$RETRIEVAL_DEPTH, max_rules=$MAX_RULES)"
echo "  Output: $SHARED_DIR"
echo "========================================================"

write_config "False" "../results/critic_eval"
mkdir -p "$SHARED_DIR"
cd "$SCRIPT_DIR/src"

echo "[$(date)] Stage 1: Rule Generation"
python3 auto_gen_rule.py

echo "[$(date)] Stage 2a: Right Code Generation"
python3 auto_gen_right_code.py right

echo "[$(date)] Stage 2b: Wrong Code Generation"
python3 auto_gen_right_code.py wrong

cd "$SCRIPT_DIR"

# ── Copy Stage 2 output for the Critic run ────────────────────────────────────
echo ""
echo "[$(date)] Copying Stage 2 output for Critic run..."
rm -rf "$CRITIC_DIR"
cp -r "$SHARED_DIR" "$CRITIC_DIR"
rm -rf "$CRITIC_DIR/out_refinement"   # ensure Stage 3 starts clean

# ── Stage 3 WITHOUT Critic ────────────────────────────────────────────────────
echo ""
echo "========================================================"
echo "  Stage 3: Refinement  [Critic: OFF]"
echo "  Output: $SHARED_DIR/out_refinement/"
echo "========================================================"

write_config "False" "../results/critic_eval"
cd "$SCRIPT_DIR/src"
python3 auto_gen_final_parse.py

cd "$SCRIPT_DIR"

# ── Stage 3 WITH Critic ───────────────────────────────────────────────────────
echo ""
echo "========================================================"
echo "  Stage 3: Refinement  [Critic: ON]"
echo "  Output: $CRITIC_DIR/out_refinement/"
echo "========================================================"

write_config "True" "../results/critic_eval_with_critic"
cd "$SCRIPT_DIR/src"
python3 auto_gen_final_parse.py

cd "$SCRIPT_DIR"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "========================================================"
echo "  Done at $(date)"
echo ""
echo "  Without Critic : $SHARED_DIR/out_refinement/"
echo "  With Critic    : $CRITIC_DIR/out_refinement/"
echo ""
echo "  Next step:"
echo "    python3 src/eval_critic_judge.py"
echo "========================================================"
