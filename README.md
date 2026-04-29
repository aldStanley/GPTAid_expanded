# GPTAid — Upgraded

An upgraded version of the [GPTAid framework](https://arxiv.org/abs/2409.09288) (Liu et al., NDSS 2025) for automated generation of API Parameter Security Rules (APSRs) via LLM reasoning and execution feedback.

This project extends the original 3-stage pipeline with two enhancements:
- **Bounded Inter-procedural Retrieval Layer** (Stage 1): dynamically retrieves callee source code up to depth `k` to enrich context.
- **Critic Agent** (Stage 3): a verifier agent that cross-checks proposed APSRs against code diffs, discarding false positives.

> **NOTE: Running Stage 2 outside Docker requires `sudo` and host library setup. The Docker sandbox is strongly recommended.**

---

## Deliverables

| Artifact | Location | Description |
|---|---|---|
| Source code | `src/` | Pipeline stages 1–3, helpers |
| Prompt templates | `prompt/` | LLM prompt files for each stage |
| Pipeline scripts | `run_pipeline.sh`, `ablation_*.sh`, `eval_critic.sh`, `clear_output.sh` | End-to-end execution and ablation |
| Configuration | `config.json` | Runtime parameters |
| Dataset | `test_info/` | 20 libpcap APIs, call graph, per-function source |
| Pre-run results | `results/` | Ablation outputs — see [Evaluation](#evaluation) section |
| Context measurement | `measure_context.py` | Measures Stage 1 prompt token counts across retrieval depths |
| Milestone documents | `milestones/` | Proposal, progress report, and future submissions |

---

## Milestones

All assignment submissions are in the `milestones/` folder:

| Document | File |
|---|---|
| Project Proposal | `milestones/Project_Proposal.pdf` |
| Progress Report | `milestones/Progress_Report.pdf` |
| Demo Slides | `milestones/Demo.pdf` |
| Final Report | `milestones/Final_Report.pdf` |
| Framework Diagram | `milestones/Famework_Diagram.pdf` |
---

## Repository Structure

```
├── src/
│   ├── auto_gen_rule.py          # Stage 1 — raw APSR generation
│   ├── auto_gen_right_code.py    # Stage 2 — correct/violation code generation & execution
│   ├── auto_gen_final_parse.py   # Stage 3 — rule refinement (+ Critic Agent)
│   ├── parse_wrong_diff.py       # Helper: code-diff parsing
│   ├── identify_error.py         # Helper: runtime error classification
│   └── preprocess/
│       ├── get-graph-treesitter.py   # Extract per-function source code
│       └── gen_callgraph.py          # Build inter-procedural call graph
│
│
├── test_info/                # Input data and pipeline working directory
│   ├── api_info/             # api_list (target APIs) and call_graph
│   ├── libpcap/              # libpcap source used for evaluation
│   ├── libpcap-funcs/        # Preprocessed per-function source files
│   ├── out_gen_rule/         # Stage 1 output (raw APSRs)
│   ├── out_wrong_code/       # Stage 2 output (generated code + execution logs)
│   └── out_refinement/       # Stage 3 output (final APSRs, auto_rule_info)
│
├── results/                  # Ablation study results (pre-run)
│   ├── baseline/             # No enhancements
│   ├── dynamicOnly/          # Retrieval only (depth=1)
│   ├── criticOnly/           # Critic Agent only
│   ├── full/                 # Both enhancements (depth=1)
│   ├── max20/                # max_rules_per_api=20 sweep
│   ├── max50/                # max_rules_per_api=50 sweep
│   └── depth2/               # retrieval_depth=2 sweep (Stage 1 only; Stages 2–3 not yet run)
│
├── milestones/               # Assignment submissions
│   ├── Project_Proposal.pdf
│   └── Progress_Report.pdf
│   └── Demo.pdf
│   └── Framework_Diagram.png
│   └── Final_Report.pdf
│
├── config.json               # Runtime configuration (see Deploy section)
├── .env                      # API keys — create this file, never commit it
├── Dockerfile                # Sandbox image for Stage 2 compilation
├── requirements.txt          # Python dependencies
├── measure_context.py        # Measure Stage 1 prompt size at retrieval depth 0/1/2
├── run_pipeline.sh           # Run all 3 stages end-to-end
├── ablation_max20.sh         # Ablation: all 4 variants at max_rules=20
├── ablation_max50.sh         # Ablation: all 4 variants at max_rules=50
├── ablation_depth2.sh        # Ablation: dynamicOnly + full at depth=2
└── clear_output.sh           # Wipe stage outputs for a clean re-run
```

---

## External Software

| Dependency | Purpose | Source |
|---|---|---|
| **GPTAid** (original) | Base 3-stage APSR pipeline this project extends | [arXiv:2409.09288](https://arxiv.org/abs/2409.09288) |
| **cinspector** | C source code inspection and AST traversal (vendored in `cinspector/`) | [github.com/PeiweiHu/cinspector](https://github.com/PeiweiHu/cinspector) |
| **Tree-sitter** (`tree-sitter==0.20.1`) | C code parsing for the preprocessing scripts | [tree-sitter.github.io](https://tree-sitter.github.io) |
| **Google Gemini API** (`google-generativeai`) | LLM backend for all three stages (replaces OpenAI from the original paper) | [ai.google.dev](https://ai.google.dev) |

---

## Build

### Prerequisites

- Python 3.9+
- Docker (recommended for Stage 2)
- `gcc` and `valgrind` (only needed when running Stage 2 without Docker)

### Step 1 — Python dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install tiktoken tree-sitter==0.20.1
```

### Step 2 — Install cinspector

```bash
cd cinspector
pip install -e .
cd ..
```

### Step 3 — Build the Docker sandbox

Stage 2 compiles and executes generated C code. The sandbox image bundles `gcc`, `valgrind`, and all target libraries (`libpcap`, `libssl`, `libsqlite3`, `libxml2`).

```bash
docker build -t gptaid-sandbox .
```

---

## Deploy and Run

### Step 1 — Configure API credentials

Create a `.env` file in the project root (it is git-ignored):

```
GEMINI_API_KEY=<your-gemini-api-key>
GEMINI_MODEL=gemini-2.5-flash-lite
```

`GEMINI_MODEL` is optional and defaults to `gemini-2.0-flash`. See `src/auto_gen_rule.py` for the pricing table of supported models.

`ROOT_PASSWD` is only needed when running Stage 2 **without** Docker:

```
ROOT_PASSWD=<your-sudo-password>
```

### Step 2 — Edit `config.json`

```json
{
    "retrieval_depth": 1,
    "use_docker": true,
    "docker_image": "gptaid-sandbox",
    "critic_agent": false,
    "result_dir": "../results/full",
    "max_rules_per_api": 5
}
```

| Field | Description |
|---|---|
| `retrieval_depth` | `0` = baseline (no retrieval), `1` = fetch direct callees, `2` = fetch two levels deep |
| `use_docker` | `true` to run Stage 2 inside the Docker sandbox (recommended) |
| `docker_image` | Name of the Docker image built in the Build step |
| `critic_agent` | `true` to enable the Stage 3 Critic Agent |
| `result_dir` | Output directory for this run (relative to `src/`) |
| `max_rules_per_api` | Maximum raw APSRs generated per API in Stage 1 |

### Step 3 — (Optional) Preprocess a new library

Skip this step if using the included `libpcap` data in `test_info/`.

```bash
cd src/preprocess
# Edit project_dir, lib_name, out_dir at the top of each script first
python3 get-graph-treesitter.py   # extract per-function source files
python3 gen_callgraph.py          # build call graph
cd ../..
```

### Step 4 — Run the pipeline

**Full pipeline (all 3 stages):**

```bash
./run_pipeline.sh
```

**Or run stages individually from `src/`:**

```bash
cd src
python3 auto_gen_rule.py                  # Stage 1: generate raw APSRs
python3 auto_gen_right_code.py right      # Stage 2a: generate correct-usage code
python3 auto_gen_right_code.py wrong      # Stage 2b: generate violation code
python3 auto_gen_final_parse.py           # Stage 3: refine and finalize APSRs
```

Final APSRs and per-API metrics are written to `<result_dir>/out_refinement/auto_rule_info`.

### Ablation Study

The ablation scripts run all variants automatically, writing results under `results/`:

```bash
./ablation_max20.sh    # baseline / dynamicOnly / criticOnly / full at max_rules=20
./ablation_max50.sh    # same four variants at max_rules=50
./ablation_depth2.sh   # dynamicOnly + full at retrieval_depth=2
```

### Resetting stage outputs

Each stage caches results and skips already-processed APIs on re-runs. Use `clear_output.sh` to reset:

```bash
./clear_output.sh 1      # clear Stage 1 output (out_gen_rule)
./clear_output.sh 2      # clear Stage 2 output (out_wrong_code)
./clear_output.sh 3      # clear Stage 3 output (out_refinement)
./clear_output.sh all    # clear all stages
```

---

## Evaluation

### Dataset

The evaluation uses **20 libpcap APIs** drawn from the same benchmark used in the original GPTAid paper.

| Artifact | Location in this repo | Description |
|---|---|---|
| API list | `test_info/api_info/api_list` | 20 libpcap function names, one per line |
| Call graph | `test_info/api_info/call_graph` | JSONL file mapping each API to its callee graph |
| Library source | `test_info/libpcap/pcap.c` | libpcap source file (upstream: [github.com/the-tcpdump-group/libpcap](https://github.com/the-tcpdump-group/libpcap)) |
| Preprocessed functions | `test_info/libpcap-funcs/` | Per-function source files extracted by the preprocessing step |
| Pre-run results | `results/` | Output of all ablation runs (see table below) |

The 20 APIs covered are: `pcap_snapshot`, `pcap_is_swapped`, `pcap_major_version`, `pcap_create`, `pcap_open_dead_with_tstamp_precision`, `pcap_findalldevs`, `pcap_set_promisc`, `pcap_list_datalinks`, `pcap_parsesrcstr_ex`, `pcap_list_tstamp_types`, `pcap_set_tstamp_type`, `pcap_activate`, `pcap_set_snaplen`, `pcap_close`, `pcap_setfilter`, `pcap_lookupdev`, `pcap_next_ex`, `pcap_set_timeout`, `pcap_strerror`, `pcap_set_buffer_size`.

### Baseline (Alternative System)

The **baseline** configuration reproduces the original GPTAid pipeline — no inter-procedural retrieval (`retrieval_depth=0`) and no Critic Agent (`critic_agent=false`) — on the same dataset and LLM. This serves as the direct comparison system for measuring the contribution of each proposed enhancement. The baseline results are stored in `results/baseline/`.

The original GPTAid system (Liu et al., NDSS 2025) is described in [arXiv:2409.09288](https://arxiv.org/abs/2409.09288) and its source code is available at [github.com/ise-uiuc/GPTAid](https://github.com/ise-uiuc/GPTAid). Note that the original system used GPT-4 and a different (larger) dataset; our baseline is a faithful re-implementation of its pipeline logic on the libpcap benchmark using Gemini.

### Metrics

All metrics are computed automatically from `<result_dir>/out_refinement/auto_rule_info` (one JSON object per API per line):

| Metric | Field(s) | Definition |
|---|---|---|
| Stage-1 Rules | `Orig_Rule_Num` | Raw APSRs generated by Stage 1 per API |
| Final Rules | `Final_Rule_Num` | APSRs surviving Stage-2/3 validation |
| Valid Violations | `Wrong_Code_Success_Num` | Violation code cases that triggered expected runtime errors |
| Invalid Violations | `Wrong_Code_Faild_Num` | Violation code cases that did **not** trigger errors (false positives) |
| **Precision** | both above | `Valid / (Valid + Invalid)` — fraction of validated rules that correctly identify real violations |
| Cost | `All_Cost_USD` | Gemini API spend for this API |

### Replicating the Evaluation

#### Notice
Due to LLM's undeterminism, it is nearly impossible to replicate the exact same result, but the relative result should be consistent (e.g. precision increases when the Retrieval Layer is active).

#### Prerequisites

Complete all steps in the **Build** section above. Confirm Docker is running:

```bash
docker image ls | grep gptaid-sandbox
```

Set your Gemini credentials in `.env` (see Deploy section). The evaluation dataset and preprocessed call graph are already in `test_info/` — no additional download is required.

#### Option A — Run a single configuration

Edit `config.json` to select the desired variant, then:

```bash
# Example: full system (retrieval depth=1, critic agent enabled)
# config.json: { "retrieval_depth": 1, "critic_agent": true, "result_dir": "../results/my_full", ... }
./run_pipeline.sh
```

Results appear in the directory specified by `result_dir` in `config.json`.

#### Option B — Run the full ablation study

Three ablation scripts each run all four component variants automatically:

```bash
# Component ablation at max_rules_per_api = 20
./ablation_max20.sh          # writes to results/max20/{baseline,criticOnly,dynamicOnly,full}/

# Component ablation at max_rules_per_api = 50
./ablation_max50.sh          # writes to results/max50/{...}/

# Retrieval depth ablation (dynamicOnly + full at depth=2, max_rules=20)
./ablation_depth2.sh         # writes to results/depth2/{dynamicOnly,full}/
```

Each script runs four sequential pipeline passes and logs output to `results/<sweep>/logs/<variant>.log`. Expected wall-clock time per variant: ~10–30 minutes depending on API rate limits and the number of APIs.

To run the default-parameter component ablation (the main Table 1 results, `max_rules_per_api=5`), set each configuration manually and run `run_pipeline.sh`, or set `config.json` fields as follows for each variant:

| Variant | `retrieval_depth` | `critic_agent` | `result_dir` |
|---|---|---|---|
| baseline | `0` | `false` | `"../results/baseline"` |
| dynamicOnly | `1` | `false` | `"../results/dynamicOnly"` |
| criticOnly | `0` | `true` | `"../results/criticOnly"` |
| full | `1` | `true` | `"../results/full"` |

#### Reading results

Each completed run writes `auto_rule_info` to `<result_dir>/out_refinement/`. To extract summary metrics across all 20 APIs:

```python
import json, pathlib

def summarize(path):
    data = [json.loads(l) for l in pathlib.Path(path).read_text().splitlines() if l.strip()]
    ws = sum(d['Wrong_Code_Success_Num'] for d in data)
    wf = sum(d['Wrong_Code_Faild_Num'] for d in data)
    return {
        'apis': len(data),
        'stage1_rules': sum(d['Orig_Rule_Num'] for d in data),
        'final_rules':  sum(d['Final_Rule_Num'] for d in data),
        'precision':    round(ws / (ws + wf) * 100, 1) if (ws + wf) else 0,
        'cost_usd':     round(sum(d['All_Cost_USD'] for d in data), 4),
    }

print(summarize('results/full/out_refinement/auto_rule_info'))
```

Pre-run results for all ablation configurations are committed to `results/` so the numbers can be inspected without re-running the pipeline.


## Depth Comparison (Single-API Context Analysis)

`results/depth_compare/` contains a focused run of `pcap_list_datalinks` at `retrieval_depth=0` (baseline) and `retrieval_depth=1` with `max_rules_per_api=5`, used to compare token usage and rule quality between depths on a single API.

| Variant | Final Rules | Valid Violations | Invalid Violations | Precision | All Tokens |
|---------|-------------|------------------|--------------------|-----------|------------|
| baseline (`depth=0`) | 4 | 1 | 0 | 100% | 31,222 |
| depth=1 | 3 | 1 | 1 | 50% | 61,721 |

### Reproducing the depth_compare results

Prerequisites: Docker running (`docker ps`), `.env` configured with `GEMINI_API_KEY` and `GEMINI_MODEL`.

**Step 1 — Set the API target in test_info/api_info/api_list:**

**Step 2 — Run baseline (depth=0):**

```bash
# Edit config.json:
# { "retrieval_depth": 0, "critic_agent": false, "result_dir": "../results/depth_compare/baseline", "max_rules_per_api": 5, ... }
rm -rf results/depth_compare/baseline/out_gen_rule \
       results/depth_compare/baseline/out_wrong_code \
       results/depth_compare/baseline/out_refinement
mkdir -p results/depth_compare/baseline
./run_pipeline.sh
```

**Step 3 — Run depth=1:**

```bash
# Edit config.json:
# { "retrieval_depth": 1, "critic_agent": false, "result_dir": "../results/depth_compare/depth1", "max_rules_per_api": 5, ... }
rm -rf results/depth_compare/depth1/out_gen_rule \
       results/depth_compare/depth1/out_wrong_code \
       results/depth_compare/depth1/out_refinement
mkdir -p results/depth_compare/depth1
./run_pipeline.sh
```

**Step 4 — Read results:**

```python
import json, pathlib

for label in ['baseline', 'depth1']:
    p = pathlib.Path(f'results/depth_compare/{label}/out_refinement/auto_rule_info')
    d = json.loads(p.read_text().strip())
    ws, wf = d['Wrong_Code_Success_Num'], d['Wrong_Code_Faild_Num']
    prec = round(ws / (ws + wf) * 100, 1) if (ws + wf) else 0
    print(f"{label}: final_rules={d['Final_Rule_Num']}  precision={prec}%  tokens={d['All_Token']}")
```

### Context injection analysis (`measure_context.py`)

`measure_context.py` in the project root builds Stage-1 prompts at each depth without making LLM calls and reports character and token counts. Run it for any API in the list:

```bash
python3 measure_context.py pcap_list_datalinks
python3 measure_context.py pcap_parsesrcstr_ex   # only API with resolvable depth=2 callees
```

### Evaluation Analysis
Please refer to the Final Report under milestones/

### Use of AI
Claude Code was utilized throughout the entire implementation, including environment setup, debugging, and evaluation automation, but it was not involved in core decisions such as the high-level system architecture design or the selection of specific evaluation metrics.