#!/bin/bash
set -e

cd "$(dirname "$0")/src"

echo "=== Stage 1: Rule Generation ==="
python3 auto_gen_rule.py

echo "=== Stage 2a: Right Code Generation ==="
python3 auto_gen_right_code.py right

echo "=== Stage 2b: Wrong Code Generation ==="
python3 auto_gen_right_code.py wrong

echo "=== Stage 3: Rule Refinement ==="
python3 auto_gen_final_parse.py

echo "=== Pipeline complete ==="
