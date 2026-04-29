"""
measure_context.py — compare Stage 1 prompt context at retrieval_depth = 0, 1, 2
for a chosen API (default: pcap_activate).

Builds the exact same prompt that auto_gen_rule.py would send to the LLM, but
never makes any API calls — just prints character and token counts.
"""

import json
import os
import sys
import tiktoken

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
FUNC_INFO_PATH = os.path.join(ROOT, 'test_info', 'libpcap-funcs', '0func_info.json')
CALL_GRAPH_PATH = os.path.join(ROOT, 'test_info', 'api_info', 'call_graph')
PROMPT_TEMPLATE = os.path.join(ROOT, 'prompt', 'rule')

TARGET_API = sys.argv[1] if len(sys.argv) > 1 else 'pcap_activate'

# ── Helpers (mirrors auto_gen_rule.py) ────────────────────────────────────────

def read_json(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]

def get_value(lst, key_value, key_match):
    for item in lst:
        if item.get(key_match) == key_value:
            return item
    return None

def get_code(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ''

_LAYER_ORDINALS = {1: 'First', 2: 'Second', 3: 'Third', 4: 'Fourth', 5: 'Fifth'}

def get_callee_code(func_name, func_info_list, max_depth):
    visited = {func_name}
    result = {}
    queue = [(func_name, 0)]
    while queue:
        current, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        current_json = get_value(func_info_list, current, 'func')
        if current_json is None:
            continue
        for callee in current_json.get('other_fc', []):
            if callee in visited:
                continue
            visited.add(callee)
            callee_json = get_value(func_info_list, callee, 'func')
            if callee_json and 'path' in callee_json:
                code = get_code(callee_json['path'])
                if code:
                    result[callee] = code
            queue.append((callee, depth + 1))
    return result

def build_callee_section(callee_code_dict):
    if not callee_code_dict:
        return ''
    section = ''
    for name, code in callee_code_dict.items():
        section += f'\nSource code of called function `{name}`:\n```\n{code}\n```\n'
    return section

def build_prompt(func, func_code, template, callee_code_dict, para_name, para_index):
    prompt = template.replace('FUNC_NAME', func)
    prompt = prompt.replace('SOURCE_CODE', func_code)
    callee_section = build_callee_section(callee_code_dict)
    prompt = prompt.replace('CALLEE_CODE', callee_section)
    prompt = prompt.replace('PARA_NAME', para_name)
    prompt = prompt.replace('Parameter_Info', f'Parameter {para_index}')
    prompt = prompt.replace('ADDITIONAL', '')
    return prompt

def count_tokens(text):
    enc = tiktoken.get_encoding('cl100k_base')
    return len(enc.encode(text))

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    func_info_list = read_json(FUNC_INFO_PATH)

    func_json = get_value(func_info_list, TARGET_API, 'func')
    if func_json is None:
        print(f'ERROR: {TARGET_API} not found in func_info')
        sys.exit(1)

    func_code = get_code(func_json['path'])
    declaration = func_json.get('declaration', '')
    other_fc = func_json.get('other_fc', [])

    with open(PROMPT_TEMPLATE) as f:
        template = f.read()

    # Use first non-return parameter for a representative prompt
    # (all parameters share the same callee section; only para_name differs)
    import sys as _sys
    sys.path.insert(0, os.path.join(ROOT, 'src'))
    import parse_wrong_diff
    para_dict_list, _ = parse_wrong_diff.get_parameter_list(declaration)
    if not para_dict_list:
        para_name, para_index = 'p', 1
    else:
        para_name  = para_dict_list[0]['name']
        para_index = 1

    print(f'API:         {TARGET_API}')
    print(f'Declaration: {declaration}')
    print(f'Own source:  {len(func_code):,} chars  ({len(func_code.splitlines())} lines)')
    print(f'depth-1 callees in call graph: {other_fc}')
    print()

    rows = []
    for depth in (0, 1, 2):
        callee_code_dict = get_callee_code(TARGET_API, func_info_list, max_depth=depth)
        callee_names     = list(callee_code_dict.keys())
        callee_chars     = sum(len(c) for c in callee_code_dict.values())

        prompt = build_prompt(TARGET_API, func_code, template, callee_code_dict, para_name, para_index)
        total_chars  = len(prompt)
        total_tokens = count_tokens(prompt)

        rows.append((depth, callee_names, callee_chars, total_chars, total_tokens))

        print(f'── depth={depth} ──────────────────────────────────────────')
        print(f'  Callees fetched:   {callee_names if callee_names else "(none)"}')
        print(f'  Callee source:     {callee_chars:,} chars')
        print(f'  Total prompt:      {total_chars:,} chars  |  {total_tokens:,} tokens')

    n_params = len(para_dict_list) if para_dict_list else 1

    print()
    print('── Delta summary (per prompt) ──────────────────────────')
    d0_chars, d0_tok = rows[0][3], rows[0][4]
    prev_chars, prev_tok = d0_chars, d0_tok
    for depth, names, callee_chars, total_chars, total_tokens in rows[1:]:
        delta_from_0    = total_tokens - d0_tok
        delta_from_prev = total_tokens - prev_tok
        pct_chars       = (total_chars - d0_chars) / d0_chars * 100
        print(f'  depth={depth} vs depth=0:    +{total_chars - d0_chars:,} chars ({pct_chars:+.1f}%)  |  +{delta_from_0:,} tokens')
        if depth > 1:
            print(f'  depth={depth} vs depth={depth-1}:    +{total_chars - prev_chars:,} chars            |  +{delta_from_prev:,} tokens')
        print(f'             new callees: {names}')
        print()
        prev_chars, prev_tok = total_chars, total_tokens

    print(f'── Total across all {n_params} parameter prompts ─────────────────')
    d1_tok = rows[1][4]
    d2_tok = rows[2][4]
    print(f'  depth=1 total tokens: {d1_tok * n_params:,}  ({d1_tok:,} × {n_params} params)')
    print(f'  depth=2 total tokens: {d2_tok * n_params:,}  ({d2_tok:,} × {n_params} params)')
    print(f'  depth=2 extra tokens: +{(d2_tok - d1_tok) * n_params:,}  (+{d2_tok - d1_tok:,} × {n_params} params)')


if __name__ == '__main__':
    main()
