import json
import logging
import os
import re
from typing import TypedDict, Sequence

from langchain_ollama import ChatOllama
from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.graph import StateGraph, END

from governance import AIGovernanceGuard
from rag_engine import ThreatKnowledgeBase
from sigma_tools import calculate_coverage_gap, normalize_sigma_tag_to_technique_id, parse_sigma_rule

logger = logging.getLogger("agent_system")

TECHNIQUE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
MAX_RETRIES = 1


# Define Agent State
class AgentState(TypedDict):
    messages: Sequence[BaseMessage]
    caller_id: str
    raw_rule: str
    parsed_metadata: dict
    retrieved_context: list
    gap_analysis: dict
    final_report: str
    retry_count: int


# Instantiate Core Tools
guard = AIGovernanceGuard()
rag = ThreatKnowledgeBase()

# Model choice & determinism are explicit, not accidental:
# - llama3.1:8b runs on commodity hardware with no per-call API cost, trading
#   some reasoning depth for latency/cost at scale. Swap via LLM_MODEL to a
#   larger reasoning model when accuracy matters more than throughput.
# - temperature=0 + a fixed seed make "same rule in -> same report out" hold,
#   which matters for a tool whose job is consistent coverage grading.
LLM_MODEL = os.environ.get("LLM_MODEL", "llama3.1:8b")
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0"))
LLM_SEED = int(os.environ.get("LLM_SEED", "42"))
llm = ChatOllama(model=LLM_MODEL, temperature=LLM_TEMPERATURE, seed=LLM_SEED)


# Node 1: Access Control + Input Governance & Pre-processing
def input_node(state: AgentState):
    caller_id = state.get("caller_id", "local-user")
    if not guard.authorize(caller_id):
        raise PermissionError(f"Caller '{caller_id}' is not authorized to submit detection rules.")

    raw_rule = state["raw_rule"]
    is_valid, sanitized_rule = guard.validate_input(raw_rule)
    if not is_valid:
        raise ValueError(f"Input failed security validation: {sanitized_rule}")
    return {"raw_rule": sanitized_rule}


# Node 2: Sigma Rule Parsing (same shared logic the MCP server exposes)
def parse_node(state: AgentState):
    parsed = parse_sigma_rule(state["raw_rule"])
    return {"parsed_metadata": parsed}


# Node 3: RAG Retrieval — query enriched with the rule's declared ATT&CK tags
def rag_analysis_node(state: AgentState):
    rule = state["raw_rule"]
    tags = state.get("parsed_metadata", {}).get("tags", [])
    query = rule if not tags else f"{rule}\n{' '.join(tags)}"
    retrieved = rag.hybrid_search(query=query, top_k=2)
    return {"retrieved_context": retrieved}


# Node 4: LLM Reasoning & Gap Assessment
def reasoning_node(state: AgentState):
    context = "\n".join(state["retrieved_context"])
    rule = state["raw_rule"]

    retry_note = ""
    if state.get("retry_count", 0) > 0:
        retry_note = (
            "\nIMPORTANT: your previous answer did not clearly state a MITRE "
            "ATT&CK Technique ID. You MUST include at least one, in the exact "
            "format Txxxx or Txxxx.xxx.\n"
        )

    prompt = f"""
    You are an expert SOC Threat Detection Engineer.
    Given the following detection rule or log query:
    ---
    {rule}
    ---
    And the following relevant MITRE ATT&CK Knowledge Base Context:
    ---
    {context}
    ---

    Analyze the threat detection coverage:
    1. Identify mapped MITRE ATT&CK Technique ID & Name.
    2. Identify blind spots or evasion techniques attackers could use against this rule.
    3. Provide actionable recommendations to improve detection coverage.
    {retry_note}
    """

    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        content = response.content
    except Exception as e:
        logger.exception("LLM invocation failed")
        content = f"LLM reasoning failed: {e}"

    sanitized_response = guard.sanitize_output(content)
    return {"final_report": sanitized_response}


# Node 5: Self-review — bounded retry if the report never names a Technique ID
def review_node(state: AgentState):
    if TECHNIQUE_ID_PATTERN.search(state["final_report"]):
        return {}
    return {"retry_count": state.get("retry_count", 0) + 1}


def route_after_review(state: AgentState) -> str:
    has_technique_id = bool(TECHNIQUE_ID_PATTERN.search(state["final_report"]))
    if not has_technique_id and state.get("retry_count", 0) <= MAX_RETRIES:
        return "retry"
    return "continue"


# Node 6: Coverage Gap — declared ATT&CK tags vs. techniques actually discussed
def gap_node(state: AgentState):
    detected = sorted({m.group(0).upper() for m in TECHNIQUE_ID_PATTERN.finditer(state["final_report"])})
    tags = state.get("parsed_metadata", {}).get("tags", [])
    target = sorted({tid for tag in tags if (tid := normalize_sigma_tag_to_technique_id(tag))})
    return {"gap_analysis": calculate_coverage_gap(detected, target)}


# Build StateGraph Flow
builder = StateGraph(AgentState)

builder.add_node("input_validation", input_node)
builder.add_node("parse_rule", parse_node)
builder.add_node("rag_analysis", rag_analysis_node)
builder.add_node("llm_reasoning", reasoning_node)
builder.add_node("review_report", review_node)
builder.add_node("calculate_gap", gap_node)

builder.set_entry_point("input_validation")
builder.add_edge("input_validation", "parse_rule")
builder.add_edge("parse_rule", "rag_analysis")
builder.add_edge("rag_analysis", "llm_reasoning")
builder.add_edge("llm_reasoning", "review_report")
builder.add_conditional_edges(
    "review_report",
    route_after_review,
    {"retry": "llm_reasoning", "continue": "calculate_gap"},
)
builder.add_edge("calculate_gap", END)

threat_assistant_app = builder.compile()

# Example Execution
if __name__ == "__main__":
    sample_rule = """
    title: Suspicious PowerShell Command line Execution
    status: experimental
    tags:
        - attack.t1059.001
        - attack.t1053.005
    detection:
        selection:
            Image|endswith: '\\powershell.exe'
            CommandLine|contains:
                - '-nop'
                - '-w hidden'
                - '-enc'
        condition: selection
    """

    initial_state = {
        "messages": [],
        "caller_id": "local-user",
        "raw_rule": sample_rule,
        "parsed_metadata": {},
        "retrieved_context": [],
        "gap_analysis": {},
        "final_report": "",
        "retry_count": 0,
    }

    output = threat_assistant_app.invoke(initial_state)
    print("=== THREAT DETECTION COVERAGE REPORT ===")
    print(output["final_report"])
    print("\n=== ATT&CK TAG COVERAGE (declared tags vs. techniques discussed) ===")
    print(json.dumps(output["gap_analysis"], indent=2))
