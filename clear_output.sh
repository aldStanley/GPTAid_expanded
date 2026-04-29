#!/usr/bin/env bash
# Usage:
#   ./clear_output.sh 1        — clear Stage 1 output (out_gen_rule)
#   ./clear_output.sh 2        — clear Stage 2 output (out_wrong_code)
#   ./clear_output.sh 3        — clear Stage 3 output (out_refinement)
#   ./clear_output.sh all      — clear all stages

set -e

BASE="$(cd "$(dirname "$0")/test_info" && pwd)"

STAGE1_DIR="$BASE/out_gen_rule"
STAGE2_DIR="$BASE/out_wrong_code"
STAGE3_DIR="$BASE/out_refinement"

# Files/dirs that are outputs (not inputs).
# call_graph and target_api in stage 2/3 are auto-copied from api_info on each run.
COMMON_OUTPUT_FILES=("auto_rule_info" "exists_log" "call_graph" "target_api")

clear_stage() {
    local dir="$1"
    local label="$2"

    if [ ! -d "$dir" ]; then
        echo "  $label: directory not found, skipping."
        return
    fi

    echo "  Clearing $label ($dir)..."

    # Remove known log/metadata files
    for f in "${COMMON_OUTPUT_FILES[@]}"; do
        if [ -e "$dir/$f" ]; then
            rm -rf "$dir/$f"
            echo "    removed $f"
        fi
    done

    # Remove gpt_re cache directory
    if [ -d "$dir/gpt_re" ]; then
        rm -rf "$dir/gpt_re"
        echo "    removed gpt_re/"
    fi

    # Remove per-API output subdirectories (any subdirectory that is not gpt_re)
    while IFS= read -r -d '' api_dir; do
        name="$(basename "$api_dir")"
        if [ "$name" != "gpt_re" ]; then
            rm -rf "$api_dir"
            echo "    removed $name/"
        fi
    done < <(find "$dir" -mindepth 1 -maxdepth 1 -type d -print0)

    echo "  Done."
}

usage() {
    echo "Usage: $0 {1|2|3|all}"
    echo "  1   — Stage 1: rule generation   (out_gen_rule)"
    echo "  2   — Stage 2: code generation   (out_wrong_code)"
    echo "  3   — Stage 3: rule refinement   (out_refinement)"
    echo "  all — all stages"
    exit 1
}

[ $# -ne 1 ] && usage

case "$1" in
    1)
        echo "=== Clearing Stage 1 ==="
        clear_stage "$STAGE1_DIR" "Stage 1"
        ;;
    2)
        echo "=== Clearing Stage 2 ==="
        clear_stage "$STAGE2_DIR" "Stage 2"
        ;;
    3)
        echo "=== Clearing Stage 3 ==="
        clear_stage "$STAGE3_DIR" "Stage 3"
        ;;
    all)
        echo "=== Clearing all stages ==="
        clear_stage "$STAGE1_DIR" "Stage 1"
        clear_stage "$STAGE2_DIR" "Stage 2"
        clear_stage "$STAGE3_DIR" "Stage 3"
        ;;
    *)
        usage
        ;;
esac

echo ""
echo "Clear complete. Re-run the pipeline from the cleared stage(s)."
