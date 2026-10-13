"""Small hand-labeled retrieval evaluation harness.

Measures hit@k (did the expected technique ID appear in the top-k results?)
for dense-only, sparse-only, and hybrid (RRF) search over the MITRE ATT&CK
knowledge base, so retrieval quality is a measured number, not a claim.

Run: python evaluate_retrieval.py
"""

from rag_engine import ThreatKnowledgeBase

# (query, expected MITRE technique ID) — hand-labeled against mitre_attack.json
EVAL_SET = [
    ("powershell encoded command execution", "T1059.001"),
    ("dumping credentials from lsass process memory", "T1003.001"),
    ("attacker schedules a task for persistence", "T1053.005"),
    ("clearing windows event logs to hide activity", "T1070.001"),
    ("ransomware encrypts files for impact", "T1486"),
    ("phishing email with a malicious attachment", "T1566.001"),
    ("using valid stolen account credentials to log in", "T1078"),
    ("remote desktop protocol used for lateral movement", "T1021.001"),
    ("injecting code into another running process", "T1055"),
    ("registry run key used for startup persistence", "T1547.001"),
]


def hit_at_k(results: list[str], expected_id: str, k: int) -> bool:
    return any(expected_id in r for r in results[:k])


def evaluate(kb: ThreatKnowledgeBase, k: int = 3) -> dict[str, float]:
    methods = {
        "dense_only": kb.dense_search,
        "sparse_only": kb.sparse_search,
        "hybrid_rrf": kb.hybrid_search,
    }
    scores = {}
    for name, search_fn in methods.items():
        hits = sum(hit_at_k(search_fn(query, top_k=k), expected, k) for query, expected in EVAL_SET)
        scores[name] = round(hits / len(EVAL_SET), 2)
    return scores


if __name__ == "__main__":
    kb = ThreatKnowledgeBase()
    for k in (1, 3):
        print(f"\nhit@{k} over {len(EVAL_SET)} labeled queries:")
        for method, score in evaluate(kb, k=k).items():
            print(f"  {method:12s} {score:.2f}")
