# Code Walkthrough — Threat Detection Assistant

My own notes on the project I built, documented line by line for anyone
onboarding onto it (including future me). Read this alongside the actual
files open in your editor, in dependency order, not alphabetical.

## Mental model first

```
governance.py   → access control + safety layer (used BY agent_system.py)
sigma_tools.py  → shared, pure tool logic (used BY both agent_system.py AND mcp_server.py)
rag_engine.py   → hybrid knowledge/retrieval layer (used BY agent_system.py)
agent_system.py → orchestrates all of the above into a LangGraph pipeline (the "app")
mcp_server.py   → exposes sigma_tools.py over MCP, for any MCP client
evaluate_retrieval.py → measures retrieval quality against a labeled query set
```

The key structural change from the first version of this project:
`sigma_tools.py` is now a *shared* module — the exact same parsing/gap-calc
functions are used inside the agent graph **and** exposed as MCP tools, so
there's one implementation instead of two drifting copies.

---

## 1. `governance.py` — access control, safety guardrail, and audit trail

```python
import json, logging, os, re
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_AUDIT_LOG_PATH = Path(__file__).parent / "audit_log.jsonl"
```
`Path(__file__).parent` anchors the default audit log next to this file
regardless of the caller's working directory — important once this class is
imported from different entry points (`agent_system.py`, tests, etc.).

```python
class AIGovernanceGuard:
    def __init__(self, audit_log_path: Path | str = DEFAULT_AUDIT_LOG_PATH):
        self.pii_patterns = [
            r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
            r"(?i)aws_?(?:access_?key_?id|secret_?access_?key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}['\"]?",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"(?i)bearer\s+[A-Za-z0-9\-_.]{20,}",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        ]
```
Five patterns now instead of two: the original API-key and email regexes,
plus AWS access/secret key fields, literal `AKIA...` key IDs, and generic
bearer tokens. Still regex-based — broader than before, not exhaustive.

```python
        self.injection_terms = [
            "ignore previous instructions",
            "ignore all previous instructions",
            "disregard previous instructions",
            "system override",
            "you are now unfiltered",
            "jailbreak",
        ]
        self.audit_log_path = Path(audit_log_path)
```
A few more injection phrase variants, and the audit log path is now
*injectable* (a constructor parameter) — useful for pointing tests at a
temp file instead of polluting the real audit log, which is exactly how I
smoke-tested this.

```python
    def authorize(self, caller_id: str) -> bool:
        allowed = os.environ.get("GOVERNANCE_ALLOWED_CALLERS")
        if not allowed:
            self._audit("authz_check", f"caller={caller_id!r} allowed=True (no allow-list configured)")
            return True
        allowed_ids = {c.strip() for c in allowed.split(",") if c.strip()}
        is_allowed = caller_id in allowed_ids
        self._audit("authz_check", f"caller={caller_id!r} allowed={is_allowed}")
        return is_allowed
```
**New method**: a basic access-control check. If `GOVERNANCE_ALLOWED_CALLERS`
isn't set, it's open by default (documented, not hidden) — set it to a
comma-separated list of caller IDs to restrict who can submit rules. Every
call is audited regardless of outcome, so "who tried to call this and were
they allowed" is always reconstructable from the log.

```python
    def validate_input(self, user_prompt: str) -> tuple[bool, str]:
        normalized = self._normalize(user_prompt)
        for term in self.injection_terms:
            if term in normalized:
                self._audit("input_blocked", f"matched injection term: {term!r}")
                return False, f"Governance Alert: Prompt rejected due to potential injection keyword ('{term}')."

        cleaned_prompt = user_prompt
        for pattern in self.pii_patterns:
            cleaned_prompt, n = re.subn(pattern, "[REDACTED_SENSITIVE_DATA]", cleaned_prompt)
            if n:
                self._audit("input_redacted", f"pattern matched {n} time(s): {pattern}")
        return True, cleaned_prompt
```
Same two-step logic as before (injection check, then PII redaction), but now
using `re.subn` instead of `re.sub` — `subn` returns `(new_string, count)`,
so I know *whether* and *how many times* each pattern fired, which is what
gets written to the audit log. Note: the audit entry logs the **pattern and
count**, never the matched text itself — the log can't leak the very
secrets it's recording the redaction of.

```python
    def sanitize_output(self, llm_response: str) -> str:
        for pattern in self.pii_patterns:
            llm_response, n = re.subn(pattern, "[REDACTED_SECRET]", llm_response)
            if n:
                self._audit("output_redacted", f"pattern matched {n} time(s): {pattern}")
        return llm_response
```
Same idea applied to the LLM's response, now also audited.

```python
    @staticmethod
    def _normalize(text: str) -> str:
        return re.sub(r"\s+", " ", text.lower()).strip()
```
Collapses any run of whitespace (tabs, newlines, multiple spaces) into a
single space before lowercasing — so `"ignore   previous\ninstructions"`
still matches the denylist even when someone reformats it to dodge an exact
substring match. Still trivially beatable by actual rephrasing — this isn't
a semantic classifier, just a slightly harder string to dodge.

```python
    def _audit(self, event: str, detail: str) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, "detail": detail}
        try:
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            logger.warning("Could not write audit log entry: %s", entry)
```
Appends one JSON object per line (JSONL — easy to `tail -f` or stream into
a log pipeline later) with a UTC timestamp. Wrapped in try/except so a
disk/permissions problem with the audit log degrades to a warning instead
of crashing the whole governance check.

---

## 2. `sigma_tools.py` — the shared tool logic (new file)

This didn't exist in the first version. The Sigma-parsing and
coverage-gap logic used to live *only* inside `mcp_server.py`, disconnected
from the agent. Pulling it out here means both consumers call the exact
same, exact once-tested implementation.

```python
MAX_RULE_SIZE = 50_000  # chars — guards against oversized/abusive payloads

def parse_sigma_rule(rule_yaml_str: str) -> dict:
    if len(rule_yaml_str) > MAX_RULE_SIZE:
        return {"error": "Rule exceeds maximum allowed size", "status_code": 413}
    try:
        rule = yaml.safe_load(rule_yaml_str)
        if not isinstance(rule, dict):
            return {"error": "Rule did not parse to a mapping", "status_code": 400}
        result = {
            "title": rule.get("title", "Unknown"),
            "status": rule.get("status", "experimental"),
            "tags": rule.get("tags", []),
            "detection": rule.get("detection", {}),
            "status_code": 200,
        }
        logger.info("parse_sigma_rule ok title=%r tags=%s", result["title"], result["tags"])
        return result
    except yaml.YAMLError as e:
        logger.warning("parse_sigma_rule failed: %s", e)
        return {"error": str(e), "status_code": 400}
```
Two hardening additions versus the original: a size cap (50,000 chars — an
arbitrary but reasonable guard against someone trying to feed it a huge
payload) returned as an HTTP-413-style error, and a type check that
`yaml.safe_load` actually produced a dict (a Sigma rule should always be a
mapping — if someone passes a bare string or list, this now fails cleanly
instead of crashing later when `.get()` is called on a non-dict).

```python
def calculate_coverage_gap(detected_techniques: list[str], target_framework: list[str]) -> dict:
    detected_set = {t.upper() for t in detected_techniques}
    target_set = {t.upper() for t in target_framework}

    missing = sorted(target_set - detected_set)
    covered = sorted(detected_set & target_set)
    coverage_pct = round((len(covered) / len(target_set)) * 100, 2) if target_set else 0.0
    ...
```
Same set arithmetic as before (now with `.upper()` normalization so
`"t1059.001"` and `"T1059.001"` are treated as the same technique), still
pure/deterministic — no LLM involved, correctly so, since gap math should
never be "approximately right."

```python
def normalize_sigma_tag_to_technique_id(tag: str) -> str | None:
    match = re.match(r"attack\.t(\d{4}(?:\.\d{3})?)", tag.strip().lower())
    if not match:
        return None
    return f"T{match.group(1)}"
```
**New helper**: Sigma rules declare ATT&CK coverage as tags like
`attack.t1059.001`. This converts that into the plain `T1059.001` form used
everywhere else in the codebase, returning `None` for anything that doesn't
match the expected shape (a non-ATT&CK tag like `"windows"`, for instance) —
callers filter those out rather than treating `None` as an error.

---

## 3. `mcp_server.py` — now a thin wrapper, not an implementation

```python
from sigma_tools import calculate_coverage_gap as _calculate_coverage_gap
from sigma_tools import parse_sigma_rule as _parse_sigma_rule

mcp = MCPServer("Threat-Detection-MCP")

@mcp.tool()
def parse_sigma_rule(rule_yaml_str: str) -> dict:
    """Parses a raw YAML Sigma Rule and extracts detection logic & metadata."""
    return _parse_sigma_rule(rule_yaml_str)
```
The underscore-prefixed imports avoid a name collision: the MCP-decorated
function and the underlying shared function need the same public name
(`parse_sigma_rule`) for the tool's name to stay what MCP clients expect,
so the import is aliased and the decorated function is just a one-line
pass-through. This is the whole point of the refactor: if I fix a bug in
`sigma_tools.parse_sigma_rule`, both the MCP server *and* the agent pick up
the fix automatically — there's nothing left to keep in sync by hand.

---

## 4. `rag_engine.py` — hybrid retrieval, now with real data and real reranking

```python
    def __init__(self, mitre_data_path: str = "mitre_attack.json"):
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large")
        self.documents = self._load_documents(mitre_data_path)
        self.texts = [self._format(d) for d in self.documents]
```
`mitre_data_path` is no longer a decoration — `_load_documents` actually
reads it now.

```python
    @staticmethod
    def _load_documents(path: str) -> list[dict]:
        for candidate in (Path(path), Path(__file__).parent / path):
            try:
                with open(candidate) as f:
                    data = json.load(f)
                if data:
                    return data
            except (FileNotFoundError, json.JSONDecodeError):
                continue
        return [ ...3-entry fallback... ]
```
Tries the path as given first (so an absolute path or one relative to your
current shell still works), then falls back to a path relative to this
file's own directory (so it works regardless of where you run the script
from) and finally to the original 3-entry hardcoded sample if neither file
exists or parses — the class still works standalone with zero setup, it
just has more data available when `mitre_attack.json` is present (which it
now is, with 15 techniques).

```python
    def dense_search(self, query: str, top_k: int = 3) -> list[str]:
        results = self.vector_store.similarity_search(query, k=top_k)
        return [r.page_content for r in results]

    def sparse_search(self, query: str, top_k: int = 3) -> list[str]:
        tokenized_query = query.lower().split()
        scores = self.bm25.get_scores(tokenized_query)
        top_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:top_k]
        return [self.texts[i] for i in top_idx]
```
**New public methods.** The dense and sparse logic used to be buried inline
inside `hybrid_search` with no way to call either individually. Pulling
them out means `evaluate_retrieval.py` can measure each method *in
isolation* against the hybrid result — you can't claim hybrid search is
better without something to compare it against.

```python
    def hybrid_search(self, query: str, top_k: int = 3, rrf_k: int = 60) -> list[str]:
        dense_docs = self.vector_store.similarity_search(query, k=len(self.texts))
        dense_ranking = [d.page_content for d in dense_docs]

        tokenized_query = query.lower().split()
        bm25_scores = self.bm25.get_scores(tokenized_query)
        sparse_order = sorted(range(len(bm25_scores)), key=lambda i: bm25_scores[i], reverse=True)
        sparse_ranking = [self.texts[i] for i in sparse_order]

        scores: dict[str, float] = {}
        for rank, key in enumerate(dense_ranking, start=1):
            scores[key] = scores.get(key, 0.0) + 1.0 / (rrf_k + rank)
        for rank, key in enumerate(sparse_ranking, start=1):
            scores[key] = scores.get(key, 0.0) + 1.0 / (rrf_k + rank)

        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        return [key for key, _ in ranked[:top_k]]
```
This replaces the old "count how many lists each doc appears in" merge with
**Reciprocal Rank Fusion (RRF)**: every document gets a score of
`1 / (rrf_k + rank)` from *each* ranked list it appears in (dense and
sparse rank over the *entire* corpus here, not just the top-k, so a
document ranked, say, 4th by one method still contributes a small score
instead of being discarded outright), and the scores are summed. `rrf_k=60`
is the standard damping constant from the original RRF paper — it just
controls how much rank position 1 is worth versus rank position 10; higher
`rrf_k` flattens the differences between ranks. This is a real, named,
parameter-light reranking algorithm, not an ad hoc heuristic.

---

## 5. `agent_system.py` — six nodes, one conditional branch

```python
TECHNIQUE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
MAX_RETRIES = 1
```
Module-level constants: the regex used to detect whether the LLM's report
actually names a technique ID, and a hard cap of one retry — this keeps the
self-review loop bounded (it can never spin forever even if the model
consistently refuses to name a technique).

```python
class AgentState(TypedDict):
    messages: Sequence[BaseMessage]
    caller_id: str
    raw_rule: str
    parsed_metadata: dict
    retrieved_context: list
    gap_analysis: dict
    final_report: str
    retry_count: int
```
Two new fields versus the original: `caller_id` (who's submitting the rule,
checked by `authorize()`) and `retry_count` (how many times `llm_reasoning`
has been retried for this run).

```python
LLM_MODEL = os.environ.get("LLM_MODEL", "llama3.1:8b")
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0"))
LLM_SEED = int(os.environ.get("LLM_SEED", "42"))
llm = ChatOllama(model=LLM_MODEL, temperature=LLM_TEMPERATURE, seed=LLM_SEED)
```
The model is no longer a hardcoded string — `LLM_MODEL` lets you swap it
without touching code (e.g. to a larger reasoning model when you want more
accuracy than speed). `temperature=0` + a fixed `seed` is the deliberate
determinism choice: given the same rule, you should get the same report,
which matters for a tool whose entire job is consistent grading, not
creative writing.

```python
def input_node(state: AgentState):
    caller_id = state.get("caller_id", "local-user")
    if not guard.authorize(caller_id):
        raise PermissionError(f"Caller '{caller_id}' is not authorized to submit detection rules.")
    raw_rule = state["raw_rule"]
    is_valid, sanitized_rule = guard.validate_input(raw_rule)
    if not is_valid:
        raise ValueError(f"Input failed security validation: {sanitized_rule}")
    return {"raw_rule": sanitized_rule}
```
**Node 1**, now does access control *before* even looking at the rule
content — if the caller isn't authorized, we never touch (or audit-log the
contents of) their input at all.

```python
def parse_node(state: AgentState):
    parsed = parse_sigma_rule(state["raw_rule"])
    return {"parsed_metadata": parsed}
```
**Node 2 (new)**. Calls the exact same `sigma_tools.parse_sigma_rule` that
the MCP server exposes — this is the agent *using* the shared tool
directly as a graph step, rather than the tool only existing for external
MCP clients to call.

```python
def rag_analysis_node(state: AgentState):
    rule = state["raw_rule"]
    tags = state.get("parsed_metadata", {}).get("tags", [])
    query = rule if not tags else f"{rule}\n{' '.join(tags)}"
    retrieved = rag.hybrid_search(query=query, top_k=2)
    return {"retrieved_context": retrieved}
```
**Node 3**, now reads `parsed_metadata` from the previous node and appends
any declared ATT&CK tags to the search query — a rule tagged
`attack.t1059.001` will now retrieve more precisely even if its raw text
doesn't literally mention "PowerShell."

```python
def reasoning_node(state: AgentState):
    ...
    retry_note = ""
    if state.get("retry_count", 0) > 0:
        retry_note = ("\nIMPORTANT: your previous answer did not clearly state a MITRE "
                      "ATT&CK Technique ID. You MUST include at least one...")
    prompt = f"""... {retry_note} """
    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        content = response.content
    except Exception as e:
        logger.exception("LLM invocation failed")
        content = f"LLM reasoning failed: {e}"
    sanitized_response = guard.sanitize_output(content)
    return {"final_report": sanitized_response}
```
**Node 4**, two changes: (1) if this is a retry, the prompt gets an extra
directive demanding an explicit technique ID — the model is told *why* it's
being asked again; (2) the LLM call is now wrapped in try/except, so a
network hiccup or model error produces a readable failure message in
`final_report` instead of crashing the entire graph run.

```python
def review_node(state: AgentState):
    if TECHNIQUE_ID_PATTERN.search(state["final_report"]):
        return {}
    return {"retry_count": state.get("retry_count", 0) + 1}

def route_after_review(state: AgentState) -> str:
    has_technique_id = bool(TECHNIQUE_ID_PATTERN.search(state["final_report"]))
    if not has_technique_id and state.get("retry_count", 0) <= MAX_RETRIES:
        return "retry"
    return "continue"
```
**Node 5 (new) + routing function.** This is the self-review/reflection
step: `review_node` checks whether the report contains a technique-ID-shaped
string; if yes, it changes nothing (returns `{}` — no state update).
If no, it increments `retry_count`. `route_after_review` is the function
LangGraph calls *after* `review_node` to decide where to go next — note
it's a **separate function from the node itself**: the node mutates state,
the router reads the (already-updated) state and returns a string key.
With `retry_count` starting at 0: first failure → incremented to 1 →
`1 <= MAX_RETRIES(1)` → `"retry"` → back to `llm_reasoning`. Second failure
→ incremented to 2 → `2 <= 1` is false → `"continue"` — so it can retry
at most once, guaranteed, regardless of how many times the model keeps
failing.

```python
def gap_node(state: AgentState):
    detected = sorted({m.group(0).upper() for m in TECHNIQUE_ID_PATTERN.finditer(state["final_report"])})
    tags = state.get("parsed_metadata", {}).get("tags", [])
    target = sorted({tid for tag in tags if (tid := normalize_sigma_tag_to_technique_id(tag))})
    return {"gap_analysis": calculate_coverage_gap(detected, target)}
```
**Node 6 (new)**. `TECHNIQUE_ID_PATTERN.finditer` finds *every* technique ID
mentioned anywhere in the final report (not just whether one exists, like
`review_node` checks) — that's `detected`. `target` walks the rule's
declared tags through `normalize_sigma_tag_to_technique_id`, using a
walrus-assignment (`if (tid := ...)`) to both compute and filter in one
line — any tag that isn't ATT&CK-shaped (so `normalize_...` returns `None`)
is silently dropped rather than included as `None`. Both sets go into the
same `calculate_coverage_gap` used by the MCP tool — this closes the loop:
the rule *declares* it covers certain techniques via tags, the LLM's report
discusses certain techniques, and this node tells you the actual overlap.

```python
builder.add_edge("llm_reasoning", "review_report")
builder.add_conditional_edges(
    "review_report",
    route_after_review,
    {"retry": "llm_reasoning", "continue": "calculate_gap"},
)
builder.add_edge("calculate_gap", END)
```
This is the one genuinely **branching** edge in the graph — every other
edge is a fixed, unconditional `add_edge`. `add_conditional_edges` takes the
router function and a `path_map` dict translating its return values
(`"retry"` / `"continue"`) into actual node names. This is what turns the
graph from a straight-line pipeline into something with real agentic
control flow: the next step depends on evaluating the *current* output,
not just on position in a fixed sequence.

---

## 6. `evaluate_retrieval.py` — measuring retrieval quality (new file)

```python
EVAL_SET = [
    ("powershell encoded command execution", "T1059.001"),
    ("dumping credentials from lsass process memory", "T1003.001"),
    ...
]
```
Ten hand-labeled `(query, expected technique ID)` pairs — I wrote these by
hand, deliberately phrasing each query *differently* from the corresponding
`mitre_attack.json` description (e.g. "dumping credentials from lsass
process memory" vs. the stored text "Adversaries may attempt to access
credentials by dumping LSASS process memory") so the eval actually tests
retrieval, not exact string matching.

```python
def hit_at_k(results: list[str], expected_id: str, k: int) -> bool:
    return any(expected_id in r for r in results[:k])
```
"Did the expected technique ID show up anywhere in the top-k results?" —
the standard `hit@k` retrieval metric.

```python
def evaluate(kb: ThreatKnowledgeBase, k: int = 3) -> dict[str, float]:
    methods = {"dense_only": kb.dense_search, "sparse_only": kb.sparse_search, "hybrid_rrf": kb.hybrid_search}
    scores = {}
    for name, search_fn in methods.items():
        hits = sum(hit_at_k(search_fn(query, top_k=k), expected, k) for query, expected in EVAL_SET)
        scores[name] = round(hits / len(EVAL_SET), 2)
    return scores
```
Runs all ten queries through each of the three search methods and reports
the hit rate as a fraction — this is the actual "measured retrieval gains"
artifact: run `python evaluate_retrieval.py` and you get real numbers, not
an assertion that hybrid search is better. (For the record, when I ran it:
hybrid ties dense-only at 1.00/1.00 for hit@1/hit@3, while sparse-only alone
drops to 0.90 at hit@1 — it mis-ranks one query. See the README's RAG
section for the specific failure case.)

## Suggested reading order for fast learning

1. `governance.py` — access control, injection/PII defense, audit logging.
2. `sigma_tools.py` — the shared, pure tool logic.
3. `mcp_server.py` — a thin MCP wrapper over (2).
4. `rag_engine.py` — hybrid retrieval with RRF reranking.
5. `agent_system.py` — the payoff: all of the above wired into a branching LangGraph pipeline.
6. `evaluate_retrieval.py` — how retrieval quality is actually measured.
