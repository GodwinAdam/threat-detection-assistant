# Code Walkthrough — Threat Detection Assistant

A line-by-line tour of the four source files, in the order you should read
them (dependency order, not alphabetical). Read this alongside the actual
files open in your editor.

## Mental model first

```
governance.py   → safety layer (used BY agent_system.py)
rag_engine.py   → knowledge/retrieval layer (used BY agent_system.py)
agent_system.py → orchestrates the above into a LangGraph pipeline (the "app")
mcp_server.py   → exposes small helper tools over MCP (standalone, not used by agent_system.py)
```

`agent_system.py` is the spine of the project — it imports the other two
and wires them into a 3-step pipeline. `mcp_server.py` is a separate,
optional entry point that doesn't depend on the other three files at all.

---

## 1. `governance.py` — the safety guardrail

This class is called twice per request in the pipeline: once on the way in
(`validate_input`) and once on the way out (`sanitize_output`).

```python
import re
```
Standard library regular-expressions module — used to detect/redact patterns
like API keys and emails.

```python
class AIGovernanceGuard:
    def __init__(self):
```
A class so the compiled pattern lists are built once and reused across many
calls, instead of being rebuilt every time `validate_input` runs.

```python
        self.pii_patterns = [
            r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"  # Emails
        ]
```
Two regexes:
- **Pattern 1**: matches things like `api_key: "sk-abc123..."` or
  `API-KEY=abcdef0123456789` — the `(?i)` makes it case-insensitive, and
  `{16,}` requires at least 16 characters so short/incidental matches don't
  trigger it.
- **Pattern 2**: a standard email-address matcher (`someone@example.com`).

These are treated as "secrets/PII" and get replaced wherever they're found.

```python
        self.injection_terms = [
            "ignore previous instructions",
            "system override",
            "you are now unfiltered",
            "jailbreak"
        ]
```
A denylist of literal phrases commonly used in **prompt-injection** attacks
(trying to get an LLM to discard its system instructions). Simple substring
matching — not a substitute for a real injection classifier, but a cheap
first line of defense.

```python
    def validate_input(self, user_prompt: str) -> tuple[bool, str]:
```
Returns a 2-tuple: `(is_valid, message_or_cleaned_text)`. The `tuple[bool, str]`
syntax is a modern (Python 3.9+) built-in generic type hint — no `typing.Tuple`
import needed.

```python
        for term in self.injection_terms:
            if term in user_prompt.lower():
                return False, f"Governance Alert: Prompt rejected due to potential injection keyword ('{term}')."
```
**Step 1 of validation**: lowercase the prompt and check each banned phrase.
On the first match, short-circuit and return `False` immediately — the
calling code (`agent_system.py`) treats this as a hard stop, not a warning.

```python
        cleaned_prompt = user_prompt
        for pattern in self.pii_patterns:
            cleaned_prompt = re.sub(pattern, "[REDACTED_SENSITIVE_DATA]", cleaned_prompt)
            
        return True, cleaned_prompt
```
**Step 2**: if no injection phrase was found, run both PII regexes over the
prompt, replacing any match with a placeholder. Returns `True` plus the
*cleaned* version — note the caller gets the redacted text back, not the
original.

```python
    def sanitize_output(self, llm_response: str) -> str:
        for pattern in self.pii_patterns:
            llm_response = re.sub(pattern, "[REDACTED_SECRET]", llm_response)
        return llm_response
```
Same idea applied to the **LLM's response** before it reaches the user —
in case the model hallucinates or echoes back something that looks like a
key or email. Note this only checks the PII patterns, not the injection
terms (an LLM response isn't trying to "inject" into itself).

---

## 2. `rag_engine.py` — the knowledge base (RAG)

RAG = **Retrieval-Augmented Generation**: instead of relying purely on what
the LLM memorized during training, you retrieve relevant documents first and
paste them into the prompt as context. This file builds a tiny MITRE ATT&CK
knowledge base and searches it two different ways, then merges the results
("hybrid search").

```python
import json
from langchain_community.vectorstores import Chroma
from langchain_ollama import OllamaEmbeddings
from rank_bm25 import BM25Okapi  # type: ignore[import-untyped]
```
- `Chroma`: a local vector database (stores text as numeric embeddings and
  supports similarity search).
- `OllamaEmbeddings`: converts text into embedding vectors using a model
  served by your local Ollama instance.
- `BM25Okapi`: a classic **keyword-based** ranking algorithm (no ML/embeddings
  involved) — good at exact term matches that embeddings sometimes miss.
- The `# type: ignore` comment silences a mypy warning because `rank_bm25`
  ships without type stubs.

```python
class ThreatKnowledgeBase:
    def __init__(self, mitre_data_path="mitre_attack.json"):
```
`mitre_data_path` is accepted but — as flagged in the README — **never
actually read from disk** in this version. It's a placeholder for a future
version that loads the full MITRE STIX/JSON dataset instead of the hardcoded
sample below.

```python
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large")
```
Creates the embedding client. Every call to this object sends text to your
local Ollama server and gets back a vector (list of floats) representing its
meaning.

```python
        self.documents = [
            {"id": "T1059.001", "name": "PowerShell", "desc": "..."},
            {"id": "T1053.005", "name": "Scheduled Task", "desc": "..."},
            {"id": "T1003.001", "name": "LSASS Memory", "desc": "..."}
        ]
```
The actual "knowledge base" — three real MITRE ATT&CK technique IDs with
short descriptions, hardcoded as Python dicts (not loaded from a file).

```python
        texts = [f"{d['id']} - {d['name']}: {d['desc']}" for d in self.documents]
```
Flattens each dict into one string like
`"T1059.001 - PowerShell: Adversaries may use PowerShell..."` — this is the
format both search methods below will actually index and search over.

```python
        self.vector_store = Chroma.from_texts(
            texts=texts,
            embedding=self.embeddings,
            collection_name="mitre_attack"
        )
```
**Dense index**: sends all 3 texts through the embedding model and stores the
resulting vectors in an in-memory Chroma collection, ready for similarity
search.

```python
        tokenized_corpus = [doc.lower().split() for doc in texts]
        self.bm25 = BM25Okapi(tokenized_corpus)
```
**Sparse index**: lowercases and splits each text into a list of words (naive
whitespace tokenization), then builds a BM25 index over those word lists —
this is a pure keyword-frequency model, no neural network involved.

```python
    def hybrid_search(self, query: str, top_k: int = 3):
```
The method `agent_system.py` actually calls. Runs both search strategies and
merges them.

```python
        dense_results = self.vector_store.similarity_search(query, k=top_k)
```
Embeds the query and returns the `top_k` closest documents by vector
similarity (captures *meaning*, e.g. "creds dumping" might match "LSASS
Memory" even without shared words).

```python
        tokenized_query = query.lower().split()
        bm25_scores = self.bm25.get_scores(tokenized_query)
        top_bm25_idx = sorted(range(len(bm25_scores)), key=lambda i: bm25_scores[i], reverse=True)[:top_k]
        sparse_results = [self.documents[i] for i in top_bm25_idx]
```
Tokenizes the query the same way the corpus was tokenized, scores every
document by keyword overlap, then sorts document *indices* by score
(descending) and takes the top `k`. Captures *exact term* matches (e.g. the
literal string "PowerShell").

```python
        combined = {doc.page_content if hasattr(doc, 'page_content') else f"{doc['id']} - {doc['name']}: {doc['desc']}": 1 for doc in dense_results}
```
Builds a dict keyed by the formatted text string, seeding every dense result
with a vote count of `1`. `hasattr(doc, 'page_content')` exists because
Chroma returns LangChain `Document` objects (with a `.page_content`
attribute), not raw dicts — this line normalizes both shapes into the same
string key.

```python
        for doc in sparse_results:
            key = f"{doc['id']} - {doc['name']}: {doc['desc']}"
            combined[key] = combined.get(key, 0) + 1
```
For each BM25 result, add a vote. If a document was **also** found by dense
search, its count becomes `2` — this is the "rerank" logic: documents both
methods agree on should rank higher.

```python
        sorted_results = sorted(combined.items(), key=lambda x: x[1], reverse=True)
        return [res[0] for res in sorted_results[:top_k]]
```
Sort by vote count (2s before 1s) and return just the top `k` text strings
(discarding the counts) — this is what `agent_system.py` receives as
`retrieved_context`.

```python
if __name__ == "__main__":
    kb = ThreatKnowledgeBase()
    results = kb.hybrid_search("cmd execution and script running")
    print("Hybrid Search Results:\n", json.dumps(results, indent=2))
```
Lets you run `python rag_engine.py` directly to sanity-check retrieval in
isolation, without spinning up the LLM.

---

## 3. `agent_system.py` — the LangGraph pipeline (the app)

[LangGraph](https://github.com/langchain-ai/langgraph) models an AI workflow
as a **graph of nodes**, where each node is a plain function that receives
the current state and returns a partial update to it. This is more explicit
and debuggable than one long prompt-chaining script.

```python
from typing import TypedDict, Annotated, Sequence
import json
from langchain_ollama import ChatOllama
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langgraph.graph import StateGraph, END
from governance import AIGovernanceGuard
from rag_engine import ThreatKnowledgeBase
```
Imports the two classes explained above, plus LangGraph/LangChain building
blocks. (`Annotated`, `AIMessage`, and `json` are imported but not actually
used anywhere in this file — harmless leftovers.)

```python
class AgentState(TypedDict):
    messages: Sequence[BaseMessage]
    raw_rule: str
    parsed_metadata: dict
    retrieved_context: list
    gap_analysis: dict
    final_report: str
```
Defines the **shape of the shared state** that flows through every node.
Each node only needs to return the keys it changes — LangGraph merges the
update into this dict automatically. `parsed_metadata` and `gap_analysis`
are declared here but never populated by any node in the current graph
(reserved for future nodes, e.g. calling the MCP tools).

```python
guard = AIGovernanceGuard()
rag = ThreatKnowledgeBase()
llm = ChatOllama(model="llama3.1:8b")
```
Created once at **import time**, at module level — so building the knowledge
base (which calls out to Ollama for embeddings) happens once when the module
loads, not on every request. `ChatOllama` is the chat-model client that will
send prompts to your local `llama3.1:8b` model.

```python
def input_node(state: AgentState):
    raw_rule = state["raw_rule"]
    is_valid, sanitized_rule = guard.validate_input(raw_rule)
    if not is_valid:
        raise ValueError(f"Input failed security validation: {sanitized_rule}")
    return {"raw_rule": sanitized_rule}
```
**Node 1.** Pulls the raw rule out of state, runs it through the governance
guard. If it's rejected (prompt injection detected), raises an exception,
which halts the graph. Otherwise returns the *redacted* rule, overwriting
`raw_rule` in the shared state for downstream nodes.

```python
def rag_analysis_node(state: AgentState):
    rule = state["raw_rule"]
    retrieved = rag.hybrid_search(query=rule, top_k=2)
    return {"retrieved_context": retrieved}
```
**Node 2.** Takes the (now-sanitized) rule text and uses it directly as the
search query against the MITRE knowledge base, keeping the top 2 hybrid
results. Populates `retrieved_context`.

```python
def reasoning_node(state: AgentState):
    context = "\n".join(state["retrieved_context"])
    rule = state["raw_rule"]
    
    prompt = f"""
    You are an expert SOC Threat Detection Engineer.
    ...
    """
    
    response = llm.invoke([HumanMessage(content=prompt)])
    sanitized_response = guard.sanitize_output(response.content)
    return {"final_report": sanitized_response}
```
**Node 3.** Joins the retrieved context lines with newlines, builds a single
prompt combining the rule + context + instructions (map to MITRE technique →
find blind spots → recommend improvements), sends it to the LLM as one
`HumanMessage`, then runs the raw response back through the governance guard
before storing it as `final_report`. This is the only node that calls the LLM.

```python
builder = StateGraph(AgentState)

builder.add_node("input_validation", input_node)
builder.add_node("rag_analysis", rag_analysis_node)
builder.add_node("llm_reasoning", reasoning_node)

builder.set_entry_point("input_validation")
builder.add_edge("input_validation", "rag_analysis")
builder.add_edge("rag_analysis", "llm_reasoning")
builder.add_edge("llm_reasoning", END)

threat_assistant_app = builder.compile()
```
This is the actual **graph construction**: register the three functions as
named nodes, declare `input_validation` as the starting node, chain them
linearly (`input_validation → rag_analysis → llm_reasoning → END`), then
`.compile()` turns the builder into a runnable object (`threat_assistant_app`)
with an `.invoke(initial_state)` method. Because every edge here is a fixed,
unconditional edge, this graph is really just a 3-step pipeline — but written
using LangGraph makes it trivial to later add branching (e.g., a conditional
edge that skips `llm_reasoning` if `retrieved_context` is empty).

```python
if __name__ == "__main__":
    sample_rule = """
    title: Suspicious PowerShell Command line Execution
    ...
    """
    
    initial_state = {
        "messages": [],
        "raw_rule": sample_rule,
        "parsed_metadata": {},
        "retrieved_context": [],
        "gap_analysis": {},
        "final_report": ""
    }
    
    output = threat_assistant_app.invoke(initial_state)
    print("=== THREAT DETECTION COVERAGE REPORT ===")
    print(output["final_report"])
```
Only runs when you execute `python agent_system.py` directly (not when the
module is imported elsewhere). Builds a starting state with every
`AgentState` key present (LangGraph expects the full shape up front, even
for keys nodes will fill in later), runs the whole graph in one call, and
prints the final report. `output` is the complete final state dict — grabbing
`output["final_report"]` pulls out just what `reasoning_node` produced.

---

## 4. `mcp_server.py` — exposing tools over MCP

This file is **independent** of `agent_system.py` — it doesn't import
`governance.py` or `rag_engine.py`. It re-implements two small pieces of
useful logic (Sigma parsing, coverage-gap math) as standalone **MCP tools**,
so any MCP-compatible client (like Claude Desktop or Claude Code) can call
them directly instead of you running the CLI demo.

```python
import yaml
from mcp.server.mcpserver import MCPServer
```
`yaml` parses Sigma rules (Sigma rules are written in YAML). `MCPServer` is
the SDK class for building an MCP server — the comment above it notes this
class was renamed from `FastMCP` in mcp SDK v2.x, which is why the import
path looks different from older MCP tutorials you might find online.

```python
mcp = MCPServer("Threat-Detection-MCP")
```
Creates the server instance; the string is the server's display name as seen
by MCP clients.

```python
@mcp.tool()
def parse_sigma_rule(rule_yaml_str: str) -> dict:
    """Parses a raw YAML Sigma Rule and extracts detection logic & metadata."""
    try:
        rule = yaml.safe_load(rule_yaml_str)
        return {
            "title": rule.get("title", "Unknown"),
            "status": rule.get("status", "experimental"),
            "tags": rule.get("tags", []),
            "detection": rule.get("detection", {}),
            "status_code": 200
        }
    except Exception as e:
        return {"error": str(e), "status_code": 400}
```
The `@mcp.tool()` decorator registers this function as a **callable tool**
that an MCP client can discover and invoke (the function's docstring becomes
the tool's description shown to the client/LLM). `yaml.safe_load` parses the
YAML text into a Python dict *safely* (won't execute arbitrary Python objects,
unlike plain `yaml.load`). Pulls out the fields a Sigma rule is expected to
have, defaulting sensibly if missing, and returns a `200`-style dict; any
parse failure is caught and returned as a `400`-style error dict instead of
crashing the server.

```python
@mcp.tool()
def calculate_coverage_gap(detected_techniques: list[str], target_framework: list[str]) -> dict:
    """Compares currently covered techniques against a baseline list to identify gaps."""
    detected_set = set(detected_techniques)
    target_set = set(target_framework)
    
    missing = list(target_set - detected_set)
    coverage_pct = round((len(detected_set & target_set) / len(target_set)) * 100, 2) if target_set else 0
    
    return {
        "covered_techniques": list(detected_set & target_set),
        "missing_techniques": missing,
        "coverage_percentage": f"{coverage_pct}%"
    }
```
Pure set arithmetic — no LLM, no I/O. `target_set - detected_set` = techniques
you're *supposed* to cover but don't (the gaps). `detected_set & target_set`
= the intersection (what you actually cover that also matters). The
percentage guards against division-by-zero with the `if target_set else 0`
ternary. This is the kind of deterministic calculation you deliberately do
in *plain code* rather than asking an LLM to compute, since set math should
never be "approximately right."

```python
if __name__ == "__main__":
    mcp.run()
```
Starts the MCP server listening for a client to connect (over stdio by
default), making both decorated functions above available as tools.

---

## Glossary (concepts used across the files)

| Term | Where used | In one sentence |
|---|---|---|
| **RAG** (Retrieval-Augmented Generation) | `rag_engine.py` | Fetch relevant documents first, then hand them to the LLM as context, instead of relying on the model's memorized training data. |
| **Dense/vector search** | `Chroma.similarity_search` | Compare *meaning* by comparing embedding vectors — finds semantically similar text even with no shared words. |
| **Sparse search (BM25)** | `BM25Okapi` | Classic keyword-frequency ranking — no neural network, good at exact term matches. |
| **Hybrid search** | `hybrid_search` | Run both dense and sparse search, then merge/vote on the results so you get the strengths of both. |
| **LangGraph `StateGraph`** | `agent_system.py` | Represents an AI workflow as nodes (functions) and edges (transitions) operating on one shared state dict, instead of a linear script. |
| **Prompt injection** | `governance.py` | An attack where user input tries to override the LLM's system instructions (e.g. "ignore previous instructions"). |
| **MCP** (Model Context Protocol) | `mcp_server.py` | An open protocol for exposing tools/functions to LLM clients in a standardized, discoverable way. |

## Suggested reading order for fast learning

1. `governance.py` (shortest, no ML concepts — just regex and control flow)
2. `rag_engine.py` (introduces embeddings + BM25 + the hybrid merge)
3. `agent_system.py` (ties everything into the LangGraph pipeline — the payoff)
4. `mcp_server.py` (a different, optional way to expose logic — read last since it's independent)

For each file: read the code top to bottom once *without* this document, note
what's confusing, then read the matching section above to fill the gaps.
