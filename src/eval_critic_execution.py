"""
Critic Agent Confusion Matrix Evaluation

Builds a confusion matrix by cross-referencing two objective signals:
  - Execution ground truth: did Stage 3's violation code trigger a runtime error?
    (from out_refinement/{api}/filter_rule — only confirmed-violation rules are listed)
  - Critic decision: did the critic APPROVE or REJECT the rule?
    (from out_refinement/{api}/parse_rule-{N}-critic log files)

Confusion matrix definition (critic as a filter that should remove false-positive rules):
  - Positive class = execution-INVALID rules (truly false positives; should be removed)
  - Negative class = execution-VALID rules (truly real rules; should be kept)

  TP: critic REJECTED  an exec-INVALID rule  → correct removal
  TN: critic APPROVED  an exec-VALID   rule  → correct retention
  FP: critic REJECTED  an exec-VALID   rule  → over-rejection (removed a real rule)
  FN: critic APPROVED  an exec-INVALID rule  → missed false positive

Note: In the current pipeline the critic only evaluates exec-valid rules (those that
passed Stage 3 filtering). Exec-invalid rules are pre-filtered before the critic step.
This means TP/FN cannot be directly observed from the critic logs alone — they are
reported separately as "pre-filtered" rules removed by Stage 3 prior to critic review.
"""

import os
import sys
import json
import glob

RESULT_DIRS = ['results/criticOnly', 'results/full']


def parse_verdict(critic_path):
    with open(critic_path) as f:
        content = f.read()
    if 'VERDICT: APPROVE' in content:
        return 'APPROVE'
    if 'VERDICT: REJECT' in content:
        return 'REJECT'
    return 'UNKNOWN'


def load_filter_rule_indices(api_dir):
    """Return set of original rule indices (str) that had confirmed violations."""
    path = os.path.join(api_dir, 'filter_rule')
    indices = set()
    if not os.path.exists(path):
        return indices
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    indices.add(str(data['index']))
                except (json.JSONDecodeError, KeyError):
                    pass
    return indices


def load_cluster_mapping(api_dir):
    """
    Return dict: parse_index (int) -> list of original rule indices (str).
    Reads filter_rule-parsed; the 'index' field is the parse index.
    """
    path = os.path.join(api_dir, 'filter_rule-parsed')
    mapping = {}
    if not os.path.exists(path):
        return mapping
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    parse_idx = int(data['index'])
                    cluster = [str(x) for x in data.get('cluster_class', [])]
                    mapping[parse_idx] = cluster
                except (json.JSONDecodeError, KeyError, ValueError):
                    pass
    return mapping


def analyze_api(api_name, api_data, refinement_dir):
    """
    Returns list of per-rule dicts:
      api, orig_idx, rule_text, exec_valid, critic_decision, outcome
    """
    orig_rules = api_data.get('Orig_Rule', [])
    api_dir = os.path.join(refinement_dir, api_name)

    exec_valid_indices = load_filter_rule_indices(api_dir)
    cluster_map = load_cluster_mapping(api_dir)

    # Build orig_index -> critic_decision by inverting cluster_map
    orig_to_verdict = {}
    for parse_idx, orig_indices in cluster_map.items():
        critic_file = os.path.join(api_dir, f'parse_rule-{parse_idx}-critic')
        if os.path.exists(critic_file):
            verdict = parse_verdict(critic_file)
        else:
            verdict = 'NOT_EVALUATED'
        for orig_idx in orig_indices:
            orig_to_verdict[orig_idx] = verdict

    records = []
    for i, rule_text in enumerate(orig_rules, 1):
        orig_idx = str(i)
        exec_valid = orig_idx in exec_valid_indices
        critic_decision = orig_to_verdict.get(orig_idx, 'NOT_EVALUATED')

        if exec_valid and critic_decision == 'APPROVE':
            outcome = 'TN'   # critic correctly kept a real rule
        elif exec_valid and critic_decision == 'REJECT':
            outcome = 'FP'   # critic over-rejected a real rule
        elif exec_valid and critic_decision == 'NOT_EVALUATED':
            outcome = 'TN_no_critic'   # exec-valid but critic not run (rare)
        elif not exec_valid:
            outcome = 'pre_filtered'   # removed by Stage 3 before critic
        else:
            outcome = 'unknown'

        records.append({
            'api': api_name,
            'orig_idx': orig_idx,
            'rule': rule_text[:100].rstrip(),
            'exec_valid': exec_valid,
            'critic_decision': critic_decision,
            'outcome': outcome,
        })
    return records


def compute_matrix(records):
    counts = {'TN': 0, 'FP': 0, 'pre_filtered': 0, 'TN_no_critic': 0, 'unknown': 0}
    for r in records:
        counts[r['outcome']] = counts.get(r['outcome'], 0) + 1
    return counts


def fmt_pct(num, denom):
    if denom == 0:
        return 'N/A'
    return f'{num/denom:.1%}'


def print_report(result_dir, records):
    matrix = compute_matrix(records)

    TN = matrix['TN'] + matrix.get('TN_no_critic', 0)
    FP = matrix['FP']
    pre = matrix['pre_filtered']
    total_orig = TN + FP + pre + matrix.get('unknown', 0)
    total_critic_evaluated = TN + FP

    print(f'\n{"="*60}')
    print(f'Result directory: {result_dir}')
    print(f'{"="*60}')

    print(f'\n--- Confusion Matrix (over all {total_orig} original Stage-1 rules) ---')
    print(f'  Rules pre-filtered by Stage 3 (exec-invalid, never sent to critic):')
    print(f'    Would be TP if critic evaluated them         : {pre:>4}')
    print(f'  Rules sent to critic (exec-valid):')
    print(f'    TN  — critic APPROVED a real rule            : {TN:>4}')
    print(f'    FP  — critic REJECTED a real rule (over-rej) : {FP:>4}')
    print(f'  (FN = exec-invalid rules critic approved = 0 by design; critic only')
    print(f'   sees exec-valid rules in this pipeline)')

    print(f'\n--- Critic-only Metrics (on rules the critic evaluated) ---')
    print(f'  Total rules critic evaluated                   : {total_critic_evaluated}')
    print(f'  Approval rate (TN / evaluated)                 : {fmt_pct(TN, total_critic_evaluated)}')
    print(f'  Over-rejection rate (FP / evaluated)           : {fmt_pct(FP, total_critic_evaluated)}')

    print(f'\n--- Pipeline Filtering Summary ---')
    print(f'  Original rules (Stage 1)                       : {total_orig}')
    print(f'  Removed by Stage 3 pre-filter (exec-invalid)   : {pre}  ({fmt_pct(pre, total_orig)})')
    print(f'  Sent to critic                                  : {total_critic_evaluated}  ({fmt_pct(total_critic_evaluated, total_orig)})')
    print(f'  Removed by critic (FP)                         : {FP}  ({fmt_pct(FP, total_critic_evaluated)} of evaluated)')
    print(f'  Final rules kept                               : {TN}  ({fmt_pct(TN, total_orig)} of original)')

    # Per-API breakdown
    print(f'\n--- Per-API Breakdown ---')
    header = f"{'API':<40} {'Orig':>4} {'ExecV':>5} {'Eval':>4} {'TN':>3} {'FP':>3} {'PreFilt':>7}"
    print(header)
    print('-' * len(header))

    apis = sorted(set(r['api'] for r in records))
    for api in apis:
        api_records = [r for r in records if r['api'] == api]
        m = compute_matrix(api_records)
        tn = m['TN'] + m.get('TN_no_critic', 0)
        fp = m['FP']
        pre_api = m['pre_filtered']
        orig = len(api_records)
        exec_v = tn + fp
        evaluated = tn + fp
        print(f'{api:<40} {orig:>4} {exec_v:>5} {evaluated:>4} {tn:>3} {fp:>3} {pre_api:>7}')

    # Detailed records for any FP (over-rejections)
    fp_records = [r for r in records if r['outcome'] == 'FP']
    if fp_records:
        print(f'\n--- Over-rejected Rules (FP): {len(fp_records)} ---')
        for r in fp_records:
            print(f"  {r['api']} rule {r['orig_idx']}: {r['rule'][:80]}")
    else:
        print(f'\n  No over-rejections (FP=0): critic approved all exec-valid rules.')

    return matrix


def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    target_dirs = sys.argv[1:] if len(sys.argv) > 1 else RESULT_DIRS

    for result_dir in target_dirs:
        abs_result = os.path.join(base, result_dir)
        refinement_dir = os.path.join(abs_result, 'out_refinement')
        auto_rule_info = os.path.join(refinement_dir, 'auto_rule_info')

        if not os.path.exists(auto_rule_info):
            print(f'Skipping {result_dir}: no auto_rule_info found.')
            continue

        all_records = []
        with open(auto_rule_info) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                api_data = json.loads(line)
                api_name = api_data['Function']
                records = analyze_api(api_name, api_data, refinement_dir)
                all_records.extend(records)

        print_report(result_dir, all_records)

        # Save per-rule JSONL
        out_path = os.path.join(abs_result, 'critic_confusion_matrix.jsonl')
        with open(out_path, 'w') as f:
            for r in all_records:
                f.write(json.dumps(r) + '\n')
        print(f'\nPer-rule records saved to: {out_path}')


if __name__ == '__main__':
    main()
