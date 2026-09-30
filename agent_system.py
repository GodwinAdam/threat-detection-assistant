from typing import TypedDict, Annotated, Sequence
import json
from langchain_ollama import ChatOllama
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langgraph.graph import StateGraph, END
from governance import AIGovernanceGuard
from rag_engine import ThreatKnowledgeBase

# Define Agent State
class AgentState(TypedDict):
    messages: Sequence[BaseMessage]
    raw_rule: str
    parsed_metadata: dict
    retrieved_context: list
    gap_analysis: dict
    final_report: str

# Instantiate Core Tools
guard = AIGovernanceGuard()
rag = ThreatKnowledgeBase()
llm = ChatOllama(model="llama3.1:8b")

# Node 1: Input Governance & Pre-processing
def input_node(state: AgentState):
    raw_rule = state["raw_rule"]
    is_valid, sanitized_rule = guard.validate_input(raw_rule)
    if not is_valid:
        raise ValueError(f"Input failed security validation: {sanitized_rule}")
    return {"raw_rule": sanitized_rule}

# Node 2: Parsers & RAG Retrieval
def rag_analysis_node(state: AgentState):
    rule = state["raw_rule"]
    # Retrieve contextual MITRE techniques using hybrid search
    retrieved = rag.hybrid_search(query=rule, top_k=2)
    return {"retrieved_context": retrieved}

# Node 3: LLM Reasoning & Gap Assessment
def reasoning_node(state: AgentState):
    context = "\n".join(state["retrieved_context"])
    rule = state["raw_rule"]
    
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
    """
    
    response = llm.invoke([HumanMessage(content=prompt)])
    sanitized_response = guard.sanitize_output(response.content)
    return {"final_report": sanitized_response}

# Build StateGraph Flow
builder = StateGraph(AgentState)

builder.add_node("input_validation", input_node)
builder.add_node("rag_analysis", rag_analysis_node)
builder.add_node("llm_reasoning", reasoning_node)

builder.set_entry_point("input_validation")
builder.add_edge("input_validation", "rag_analysis")
builder.add_edge("rag_analysis", "llm_reasoning")
builder.add_edge("llm_reasoning", END)

threat_assistant_app = builder.compile()

# Example Execution
if __name__ == "__main__":
    sample_rule = """
    title: Suspicious PowerShell Command line Execution
    status: experimental
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
        "raw_rule": sample_rule,
        "parsed_metadata": {},
        "retrieved_context": [],
        "gap_analysis": {},
        "final_report": ""
    }
    
    output = threat_assistant_app.invoke(initial_state)
    print("=== THREAT DETECTION COVERAGE REPORT ===")
    print(output["final_report"])