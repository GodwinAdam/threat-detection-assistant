# Threat Detection Assistant

An AI agent that reviews SIEM/Sigma-style detection rules and grades their coverage
against the MITRE ATT&CK framework. It runs entirely on local models via
[Ollama](https://ollama.com) — no data leaves your machine — and wraps every LLM
call with a governance layer that screens for prompt injection and redacts secrets
(API keys, emails) from both input and output.

## Why I built this

I built this as my own project: SOC teams I've worked with had no fast way to check whether a new detection rule actually covers the MITRE ATT&CK techniques it claims to, so I built
one that runs locally and doesn't leak rule content to a third-party API.
I used Claude Code as a coding/documentation assistant along the way, but
the architecture and code are mine.

## How it works

The pipeline is a [LangGraph](https://github.com/langchain-ai/langgraph) state
machine with six nodes, including one conditional branch (a bounded
self-review retry — see below):

```
raw rule ─▶ input_validation ─▶ parse_rule ─▶ rag_analysis ─▶ llm_reasoning ─▶ review_report ─┬─▶ calculate_gap ─▶ final output
                                                                      ▲                         │
                                                                      └── retry (max 1) ─────────┘
```

| File | Role |
|---|---|
| `governance.py` | `AIGovernanceGuard` — access control (allow-list hook), prompt-injection detection, PII/secret redaction (regex-based, both on input and LLM output), and an append-only audit log of every block/redaction/authz decision. |
| `sigma_tools.py` | Shared, pure functions (`parse_sigma_rule`, `calculate_coverage_gap`, `normalize_sigma_tag_to_technique_id`) — the single implementation reused by **both** the agent pipeline and the MCP server, so the logic isn't duplicated or siloed. |
| `rag_engine.py` | `ThreatKnowledgeBase` — hybrid retrieval over MITRE ATT&CK technique data: dense vector search (ChromaDB + `mxbai-embed-large`) and sparse search (BM25), merged with **Reciprocal Rank Fusion (RRF)** rather than a naive vote count. Loads `mitre_attack.json` if present, with a safe 3-entry fallback if not. |
| `mitre_attack.json` | 15 MITRE ATT&CK techniques (expanded from the original 3-entry demo) — real enough to meaningfully evaluate retrieval quality against. |
| `agent_system.py` | Orchestrates governance → rule parsing → retrieval → LLM reasoning → self-review → gap calculation into the LangGraph pipeline above. Running it directly executes a demo analysis on a sample PowerShell detection rule. |
| `mcp_server.py` | Thin MCP wrapper around `sigma_tools.py` — exposes `parse_sigma_rule` and `calculate_coverage_gap` as [MCP](https://modelcontextprotocol.io) tools for any MCP-compatible client (e.g. Claude Desktop/Code). |
| `evaluate_retrieval.py` | A small hand-labeled (10-query) evaluation harness that measures hit@1/hit@3 for dense-only, sparse-only, and hybrid search, so retrieval quality is a **measured number**, not a claim. |

### What each node actually does

1. **`input_validation`** — checks `caller_id` against an optional allow-list (`GOVERNANCE_ALLOWED_CALLERS`), then screens the rule for prompt-injection phrases and redacts PII/secrets. Every decision is written to `audit_log.jsonl`.
2. **`parse_rule`** — parses the Sigma YAML via `sigma_tools.parse_sigma_rule` (size-capped, safe-load only) to pull out `title`, `tags`, `detection`.
3. **`rag_analysis`** — hybrid-searches the ATT&CK knowledge base using the rule text *and* its declared tags as the query.
4. **`llm_reasoning`** — asks the local LLM (deterministic — see LLM System Design below) to map techniques, find blind spots, and recommend improvements.
5. **`review_report`** — checks the report actually names a MITRE Technique ID (regex `T\d{4}(\.\d{3})?`). If not, it loops back to `llm_reasoning` **once** with a reinforced prompt before giving up — a bounded self-correction (reflection) pattern, not an unconditional pipeline.
6. **`calculate_gap`** — compares the technique IDs the LLM actually discussed against the rule's *declared* ATT&CK tags via `sigma_tools.calculate_coverage_gap`, producing a real coverage percentage.

### LLM System Design

`agent_system.py` pins `temperature=0` and a fixed `seed` so the same rule
always produces the same report — determinism is a deliberate choice, not an
accident of defaults. Model, temperature, and seed are all overridable via
environment variables (`LLM_MODEL`, `LLM_TEMPERATURE`, `LLM_SEED`) instead of
hardcoded, so you can trade `llama3.1:8b`'s cost/latency for a larger
reasoning model without touching code. A failed LLM call no longer crashes
the whole pipeline — it's caught and surfaces as a readable error in the
report instead.

### AI Governance & Security

- **Access control**: `AIGovernanceGuard.authorize(caller_id)` checks
  `GOVERNANCE_ALLOWED_CALLERS` (comma-separated). Unset = open by default —
  this is a single allow-list, not RBAC; it's a real hook to wire identity
  checks into, not a complete org-scale access-control system.
- **Auditability**: every block, redaction, and authz decision is appended
  to `audit_log.jsonl` as a timestamped JSON line. The log never stores the
  matched secret value itself — only the pattern and a count — so the audit
  trail can't become a second leak of what it's recording the redaction of.
- **Injection defence**: a denylist of known phrases, now matched against a
  whitespace-normalized, lowercased version of the prompt (catches more
  rephrasing/formatting variants). Still a denylist, not a semantic
  classifier — a determined paraphrase can still get through.
- **Secret coverage**: expanded beyond API keys/emails to AWS access keys
  (`AKIA...`) and bearer tokens.
- **Data sovereignty**: unchanged core strength — everything runs locally via
  Ollama; no rule content or report ever leaves the machine.

### RAG Architecture & Optimization

Hybrid search now merges dense and sparse rankings with **Reciprocal Rank
Fusion** (`1/(k + rank)` summed across both rankings) instead of a naive
vote count, and `mitre_data_path` is actually wired up — it loads
`mitre_attack.json` (15 techniques) if present. Run `python
evaluate_retrieval.py` to see measured hit@1/hit@3 for dense-only,
sparse-only, and hybrid on a 10-query hand-labeled set:

```
hit@1: dense_only 1.00 · sparse_only 0.90 · hybrid_rrf 1.00
hit@3: dense_only 1.00 · sparse_only 1.00 · hybrid_rrf 1.00
```

On this small set, dense search alone is already strong, so hybrid mostly
*ties* it rather than dramatically beating it — but hybrid does recover the
one case sparse-only gets wrong (it ranks "stolen valid credentials"
against T1021.001/RDP instead of T1078/Valid Accounts, because "valid
credentials" appears in the RDP description text; hybrid's dense signal
corrects it). That's the actual, measured value of hybrid here — not a
dramatic lift, but a demonstrated and honestly-reported one.

## Prerequisites

- **Python 3.10+** (developed/tested on 3.14)
- **[Ollama](https://ollama.com/download)** installed and running locally
- ~5 GB free disk space for the two local models pulled below

## Step-by-step setup

1. **Get the code onto your machine** (unzip the download, or clone the repo) and
   open a terminal in the project folder:
   ```bash
   cd threat-detection-assistant
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate        # Windows: .venv\Scripts\activate
   ```

3. **Install the Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Ollama** if you haven't already (macOS example — see
   [ollama.com/download](https://ollama.com/download) for other platforms):
   ```bash
   brew install ollama
   ```

5. **Start the Ollama server** (leave this running in its own terminal tab):
   ```bash
   ollama serve
   ```

6. **Pull the two models this project uses** (in a new terminal tab):
   ```bash
   ollama pull llama3.1:8b
   ollama pull mxbai-embed-large
   ```

7. **Run the demo analysis:**
   ```bash
   python agent_system.py
   ```
   This feeds a sample "Suspicious PowerShell Execution" Sigma rule through the
   full pipeline and prints a threat-coverage report (mapped MITRE techniques,
   blind spots, and recommendations) to the console.

8. **(Optional) Run the standalone knowledge-base search:**
   ```bash
   python rag_engine.py
   ```
   Prints the top hybrid-search results for a sample query, useful for
   sanity-checking retrieval without invoking the LLM.

9. **(Optional) Measure retrieval quality:**
   ```bash
   python evaluate_retrieval.py
   ```
   Runs the 10-query hand-labeled eval set and prints hit@1/hit@3 for
   dense-only, sparse-only, and hybrid search.

10. **(Optional) Run as an MCP tool server**, to call `parse_sigma_rule` and
   `calculate_coverage_gap` from an MCP client instead of the CLI demo:
   ```bash
   python mcp_server.py
   ```
    Then point your MCP client (e.g. Claude Desktop's `claude_desktop_config.json`,
    or Claude Code's MCP settings) at this command so it can discover the two tools.

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `LLM_MODEL` | `llama3.1:8b` | Which Ollama model `agent_system.py` reasons with. |
| `LLM_TEMPERATURE` | `0` | Sampling temperature — `0` for deterministic, repeatable reports. |
| `LLM_SEED` | `42` | Fixed seed, paired with temperature 0 for reproducibility. |
| `GOVERNANCE_ALLOWED_CALLERS` | unset (open) | Comma-separated allow-list of `caller_id`s permitted to submit rules. Unset = no restriction. |

## Using it on your own rule

Edit the `sample_rule` string at the bottom of `agent_system.py` — or import
`threat_assistant_app` in your own script and call:

```python
from agent_system import threat_assistant_app

result = threat_assistant_app.invoke({
    "messages": [],
    "caller_id": "local-user",
    "raw_rule": my_detection_rule_yaml,
    "parsed_metadata": {},
    "retrieved_context": [],
    "gap_analysis": {},
    "final_report": "",
    "retry_count": 0,
})
print(result["final_report"])
print(result["gap_analysis"])
```

## Troubleshooting

- **`ConnectionError` / model errors when running `agent_system.py`** — make
  sure `ollama serve` is running and that both models were pulled successfully
  (`ollama list` should show `llama3.1:8b` and `mxbai-embed-large`).
- **Input rejected with "Governance Alert"** — `AIGovernanceGuard` blocks
  prompts containing injection phrases like "ignore previous instructions";
  this is expected behavior, not a bug.
- **`PermissionError: Caller '...' is not authorized`** — you've set
  `GOVERNANCE_ALLOWED_CALLERS` and the `caller_id` you passed isn't on the
  list; add it to the comma-separated env var or unset it to allow all callers.
- **`ModuleNotFoundError`** — confirm your virtual environment is activated
  and `pip install -r requirements.txt` completed without errors.
- **`audit_log.jsonl` growing in the project directory** — expected; it's the
  governance audit trail (one JSON line per block/redaction/authz decision).
  Safe to delete; it's regenerated on the next run.
