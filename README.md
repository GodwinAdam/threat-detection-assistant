# Threat Detection Assistant

An AI agent that reviews SIEM/Sigma-style detection rules and grades their coverage
against the MITRE ATT&CK framework. It runs entirely on local models via
[Ollama](https://ollama.com) — no data leaves your machine — and wraps every LLM
call with a governance layer that screens for prompt injection and redacts secrets
(API keys, emails) from both input and output.

## How it works

The pipeline is a small [LangGraph](https://github.com/langchain-ai/langgraph)
state machine with three steps:

```
raw rule ─▶ input_validation ─▶ rag_analysis ─▶ llm_reasoning ─▶ final_report
```

| File | Role |
|---|---|
| `governance.py` | `AIGovernanceGuard` — blocks prompt-injection phrases and redacts PII/secrets (regex-based) from both the prompt going in and the LLM response coming out. |
| `rag_engine.py` | `ThreatKnowledgeBase` — hybrid retrieval (dense vector search via ChromaDB + `mxbai-embed-large` embeddings, sparse search via BM25) over a small built-in sample of MITRE ATT&CK techniques. |
| `agent_system.py` | Wires the guard, the knowledge base, and a local `llama3.1:8b` model (via `langchain-ollama`) into the LangGraph pipeline. Running it directly executes a demo analysis on a sample PowerShell detection rule. |
| `mcp_server.py` | Exposes `parse_sigma_rule` and `calculate_coverage_gap` as [MCP](https://modelcontextprotocol.io) tools, so the same logic can be called from an MCP-compatible client (e.g. Claude Desktop/Code) instead of run standalone. |

**Note:** the knowledge base currently ships with only 3 hardcoded sample
techniques (T1059.001, T1053.005, T1003.001) for demonstration. The
`mitre_data_path` argument on `ThreatKnowledgeBase` is accepted but not yet
wired up to load an external MITRE ATT&CK STIX/JSON file — swap in the full
dataset there if you want broader coverage.

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

9. **(Optional) Run as an MCP tool server**, to call `parse_sigma_rule` and
   `calculate_coverage_gap` from an MCP client instead of the CLI demo:
   ```bash
   python mcp_server.py
   ```
   Then point your MCP client (e.g. Claude Desktop's `claude_desktop_config.json`,
   or Claude Code's MCP settings) at this command so it can discover the two tools.

## Using it on your own rule

Edit the `sample_rule` string at the bottom of `agent_system.py` — or import
`threat_assistant_app` in your own script and call:

```python
from agent_system import threat_assistant_app

result = threat_assistant_app.invoke({
    "messages": [],
    "raw_rule": my_detection_rule_yaml,
    "parsed_metadata": {},
    "retrieved_context": [],
    "gap_analysis": {},
    "final_report": "",
})
print(result["final_report"])
```

## Troubleshooting

- **`ConnectionError` / model errors when running `agent_system.py`** — make
  sure `ollama serve` is running and that both models were pulled successfully
  (`ollama list` should show `llama3.1:8b` and `mxbai-embed-large`).
- **Input rejected with "Governance Alert"** — `AIGovernanceGuard` blocks
  prompts containing injection phrases like "ignore previous instructions";
  this is expected behavior, not a bug.
- **`ModuleNotFoundError`** — confirm your virtual environment is activated
  and `pip install -r requirements.txt` completed without errors.
