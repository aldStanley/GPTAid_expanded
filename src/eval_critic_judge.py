"""
eval_critic_judge.py — LLM judge for Critic Agent evaluation.

Compares two Stage 3 runs that share the same Stage 1+2 output:
  results/critic_eval/out_refinement/            (Critic OFF)
  results/critic_eval_with_critic/out_refinement/ (Critic ON)

For each rule the Critic discarded (present in baseline, absent in critic run),
an LLM judge decides whether that rule was a genuine false positive or a valid
rule incorrectly thrown away.

Metrics reported:
  - True Rejections  : discarded rules the judge confirms are false positives
  - False Rejections : discarded rules the judge says were actually valid
  - Critic Precision : True Rejections / Total Discarded
"""

import json
import os
import time
import google.generativeai as genai
from dotenv import load_dotenv

# ── Config ────────────────────────────────────────────────────────────────────
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env'))
genai.configure(api_key=os.environ.get('GEMINI_API_KEY', ''))
MODEL = os.environ.get('GEMINI_MODEL', 'gemini-2.0-flash')

BASE_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'results')
NO_CRITIC  = os.path.join(BASE_DIR, 'critic_eval',             'out_refinement')
WITH_CRITIC = os.path.join(BASE_DIR, 'critic_eval_with_critic', 'out_refinement')
STAGE2_DIR  = os.path.join(BASE_DIR, 'critic_eval',             'out_wrong_code')

JUDGE_PROMPT = """\
You are a security rule auditor for C library APIs.

You are given:
  - The source code of the target API
  - A correct usage example (compiles and runs without errors)
  - A violation code example (code that is supposed to misuse the API)
  - A proposed security rule (APSR)

Your task: decide whether the proposed rule is a VALID security constraint.

A rule is VALID if:
  1. It describes a real constraint that is actually enforced by the API source code
     (e.g. the function dereferences the pointer, checks for NULL, requires prior activation).
  2. The violation code genuinely demonstrates a misuse that could cause a runtime error
     or security issue.
  3. The rule is specific to this API's behavior, not just a generic "don't pass NULL" platitude.

A rule is INVALID (false positive) if:
  1. The API source code does not actually enforce the constraint described, or
  2. The violation code does not actually demonstrate a real misuse, or
  3. The rule is too vague to be actionable.

Target API: `{api}`
Declaration: {declaration}

API Source Code:
```c
{source_code}
```

Correct Usage Code:
```c
{right_code}
```

Violation Code:
```c
{wrong_code}
```

Proposed Security Rule:
{rule}

Answer in this exact format:
REASONING: <one or two sentences explaining your decision>
VERDICT: VALID
or
VERDICT: INVALID
"""

# ── Helpers ───────────────────────────────────────────────────────────────────

def read_jsonl(path):
    if not os.path.exists(path):
        return []
    results = []
    for line in open(path).read().strip().splitlines():
        line = line.strip()
        if line:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return results

def read_filter_rule(api_dir):
    """Return {index: rule_text} from a filter_rule file."""
    path = os.path.join(api_dir, 'filter_rule')
    if not os.path.exists(path):
        return {}
    rules = {}
    for obj in read_jsonl(path):
        rules[str(obj['index'])] = obj['rule']
    return rules

def read_file(path):
    if os.path.exists(path):
        return open(path).read().strip()
    return ''

def call_judge(prompt):
    model = genai.GenerativeModel(MODEL)
    for attempt in range(3):
        try:
            resp = model.generate_content(
                prompt,
                generation_config={'temperature': 0},
            )
            return resp.text.strip()
        except Exception as e:
            print(f'    [retry {attempt+1}] {e}')
            time.sleep(5)
    return 'ERROR'

def parse_verdict(response):
    for line in reversed(response.splitlines()):
        line = line.strip().upper()
        if 'VERDICT:' in line:
            if 'INVALID' in line:
                return 'INVALID'
            if 'VALID' in line:
                return 'VALID'
    return 'UNKNOWN'

def read_critic_reasoning(api_dir, idx):
    """Read the Critic Agent's own APPROVE/REJECT reasoning for a rule index."""
    path = os.path.join(api_dir, f'parse_rule-{idx}-critic')
    if not os.path.exists(path):
        return ''
    content = open(path).read()
    # Extract only the Critic Answer section (after the prompt)
    marker = 'Critic Answer:'
    pos = content.find(marker)
    if pos != -1:
        return content[pos + len(marker):].strip()
    return content.strip()

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    baseline_log = read_jsonl(os.path.join(NO_CRITIC,   'auto_rule_info'))
    critic_log   = read_jsonl(os.path.join(WITH_CRITIC, 'auto_rule_info'))

    if not baseline_log:
        print(f'ERROR: no auto_rule_info found at {NO_CRITIC}')
        print('Run ./eval_critic.sh first.')
        return
    if not critic_log:
        print(f'ERROR: no auto_rule_info found at {WITH_CRITIC}')
        print('Run ./eval_critic.sh first.')
        return

    baseline_map = {d['Function']: d for d in baseline_log}
    critic_map   = {d['Function']: d for d in critic_log}

    total_discarded   = 0
    true_rejections   = 0   # discarded rules that judge says are false positives (good critic decision)
    false_rejections  = 0   # discarded rules that judge says are valid (bad critic decision)
    unknown           = 0
    results_log = []

    apis = sorted(baseline_map.keys())
    print(f'Evaluating {len(apis)} APIs...\n')

    for api in apis:
        bl_entry = baseline_map.get(api, {})
        cr_entry = critic_map.get(api, {})

        bl_dir = os.path.join(NO_CRITIC,   api)
        cr_dir = os.path.join(WITH_CRITIC, api)
        s2_dir = os.path.join(STAGE2_DIR,  api)

        bl_rules = read_filter_rule(bl_dir)
        cr_rules = read_filter_rule(cr_dir)

        # Rules discarded by Critic: index present in baseline but absent in critic
        discarded_indices = set(bl_rules.keys()) - set(cr_rules.keys())

        if not discarded_indices:
            print(f'  {api}: no rules discarded, skipping')
            continue

        # Load API source code (from Stage 2 output dir)
        source_code = read_file(os.path.join(s2_dir, 'func_code.c'))
        right_code  = read_file(os.path.join(s2_dir, f'{api}.c'))
        declaration = bl_entry.get('declaration', '')
        # Fall back to callgraph declaration
        if not declaration:
            cg_path = os.path.join(NO_CRITIC, 'call_graph')
            for obj in read_jsonl(cg_path):
                if obj.get('func') == api:
                    declaration = obj.get('declaration', '')
                    break

        print(f'  {api}: {len(discarded_indices)} discarded rule(s) — indices {sorted(discarded_indices)}')

        for idx in sorted(discarded_indices):
            rule_text = bl_rules[idx]
            wrong_code = read_file(os.path.join(s2_dir, f'wrong_{api}{idx}.c'))
            critic_reasoning = read_critic_reasoning(cr_dir, idx)

            if not wrong_code:
                print(f'    [idx {idx}] violation code not found, skipping')
                unknown += 1
                total_discarded += 1
                results_log.append({
                    'api': api,
                    'index': idx,
                    'rule': rule_text,
                    'critic_reasoning': critic_reasoning,
                    'judge_verdict': 'UNKNOWN',
                    'judge_reasoning': 'violation code missing',
                    'judge_response': '',
                })
                continue

            prompt = JUDGE_PROMPT.format(
                api=api,
                declaration=declaration,
                source_code=source_code[:3000] if len(source_code) > 3000 else source_code,
                right_code=right_code[:2000]   if len(right_code) > 2000   else right_code,
                wrong_code=wrong_code[:2000]   if len(wrong_code) > 2000   else wrong_code,
                rule=rule_text,
            )

            response = call_judge(prompt)
            verdict  = parse_verdict(response)

            # Extract reasoning line
            judge_reasoning = ''
            for line in response.splitlines():
                if line.strip().upper().startswith('REASONING:'):
                    judge_reasoning = line.strip()[len('REASONING:'):].strip()
                    break

            print(f'    [idx {idx}] judge={verdict}  — {judge_reasoning[:80]}')
            if critic_reasoning:
                # Show first line of critic's own reasoning for comparison
                first_line = critic_reasoning.splitlines()[0][:80] if critic_reasoning else ''
                print(f'           critic said: {first_line}')

            total_discarded += 1
            if verdict == 'INVALID':
                true_rejections += 1
            elif verdict == 'VALID':
                false_rejections += 1
            else:
                unknown += 1

            results_log.append({
                'api': api,
                'index': idx,
                'rule': rule_text,
                'critic_reasoning': critic_reasoning,
                'judge_verdict': verdict,
                'judge_reasoning': judge_reasoning,
                'judge_response': response,
            })

    # ── Results ───────────────────────────────────────────────────────────────
    print()
    print('=' * 60)
    print('CRITIC AGENT EVALUATION RESULTS')
    print('=' * 60)
    print(f'Total discarded rules      : {total_discarded}')
    print(f'True  Rejections (INVALID) : {true_rejections}')
    print(f'False Rejections (VALID)   : {false_rejections}')
    print(f'Unknown / missing          : {unknown}')
    if total_discarded - unknown > 0:
        prec = true_rejections / (total_discarded - unknown) * 100
        print(f'Critic Precision           : {prec:.1f}%')
        print(f'  (fraction of discards that were genuine false positives)')
    print()

    # Write detailed results
    out_path = os.path.join(BASE_DIR, 'critic_judge_results.jsonl')
    with open(out_path, 'w') as f:
        for r in results_log:
            f.write(json.dumps(r) + '\n')
    print(f'Detailed results saved to: {out_path}')


if __name__ == '__main__':
    main()
