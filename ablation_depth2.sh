#!/usr/bin/env bash
# ablation_depth2.sh — run dynamicOnly and full at retrieval_depth=2, max_rules_per_api=20
# Usage: ./ablation_depth2.sh (from project root)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/config.json"
RESULTS_BASE="$SCRIPT_DIR/results/depth2"
LOG_DIR="$RESULTS_BASE/logs"

mkdir -p "$LOG_DIR"

# Save original config so it can be restored on exit
ORIG_CONFIG="$(cat "$CONFIG")"
restore_config() { echo "$ORIG_CONFIG" > "$CONFIG"; }
trap restore_config EXIT

run_variant() {
    local name="$1"
    local retrieval_depth="$2"
    local critic_agent="$3"   # Python bool: True or False
    local result_dir="../results/depth2/$name"
    local log="$LOG_DIR/${name}.log"

    echo ""
    echo "========================================================"
    echo "  Variant : $name"
    echo "  retrieval_depth=$retrieval_depth  critic_agent=$critic_agent"
    echo "  Started : $(date)"
    echo "========================================================"

    # Write config for this variant
    python3 - <<PYEOF
import json
cfg = {
    "retrieval_depth": $retrieval_depth,
    "use_docker": True,
    "docker_image": "gptaid-sandbox",
    "critic_agent": $critic_agent,
    "result_dir": "$result_dir",
    "max_rules_per_api": 20
}
with open("$CONFIG", "w") as f:
    json.dump(cfg, f, indent=4)
PYEOF

    mkdir -p "$RESULTS_BASE/$name"

    cd "$SCRIPT_DIR/src"

    local failed=0

    echo "[$(date)] Stage 1: Rule Generation" | tee -a "$log"
    python3 auto_gen_rule.py 2>&1 | tee -a "$log" || { echo "ERROR: Stage 1 failed for $name" | tee -a "$log"; failed=1; }

    if [ "$failed" -eq 0 ]; then
        echo "[$(date)] Stage 2a: Right Code Generation" | tee -a "$log"
        python3 auto_gen_right_code.py right 2>&1 | tee -a "$log" || { echo "ERROR: Stage 2a failed for $name" | tee -a "$log"; failed=1; }
    fi

    if [ "$failed" -eq 0 ]; then
        echo "[$(date)] Stage 2b: Wrong Code Generation" | tee -a "$log"
        python3 auto_gen_right_code.py wrong 2>&1 | tee -a "$log" || { echo "ERROR: Stage 2b failed for $name" | tee -a "$log"; failed=1; }
    fi

    if [ "$failed" -eq 0 ]; then
        echo "[$(date)] Stage 3: Rule Refinement" | tee -a "$log"
        python3 auto_gen_final_parse.py 2>&1 | tee -a "$log" || { echo "ERROR: Stage 3 failed for $name" | tee -a "$log"; failed=1; }
    fi

    cd "$SCRIPT_DIR"

    if [ "$failed" -eq 0 ]; then
        echo "[$(date)] Variant $name COMPLETE" | tee -a "$log"
    else
        echo "[$(date)] Variant $name FAILED — check $log" | tee -a "$log"
    fi
}

echo "Starting depth ablation (retrieval_depth=2, max_rules_per_api=20)"
echo "Results will be written to: $RESULTS_BASE"
echo "Logs: $LOG_DIR"
echo "Started: $(date)"

run_variant "dynamicOnly" 2 False
run_variant "full"        2 True

echo ""
echo "========================================================"
echo "All variants finished at $(date)"
echo "Results: $RESULTS_BASE"
echo "========================================================"
