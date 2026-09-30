import json
from langchain_community.vectorstores import Chroma
from langchain_ollama import OllamaEmbeddings
from rank_bm25 import BM25Okapi  # type: ignore[import-untyped]

class ThreatKnowledgeBase:
    def __init__(self, mitre_data_path="mitre_attack.json"):
        # 1. Initialize Local Embeddings
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large")
        
        # Sample MITRE Data load (you can download the full STIX JSON from MITRE ATT&CK)
        self.documents = [
            {"id": "T1059.001", "name": "PowerShell", "desc": "Adversaries may use PowerShell to perform actions like command execution and script running."},
            {"id": "T1053.005", "name": "Scheduled Task", "desc": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or persistent execution."},
            {"id": "T1003.001", "name": "LSASS Memory", "desc": "Adversaries may attempt to access credentials by dumping LSASS process memory."}
        ]
        
        # 2. Build Dense Index (ChromaDB)
        texts = [f"{d['id']} - {d['name']}: {d['desc']}" for d in self.documents]
        self.vector_store = Chroma.from_texts(
            texts=texts,
            embedding=self.embeddings,
            collection_name="mitre_attack"
        )
        
        # 3. Build Sparse Index (BM25)
        tokenized_corpus = [doc.lower().split() for doc in texts]
        self.bm25 = BM25Okapi(tokenized_corpus)

    def hybrid_search(self, query: str, top_k: int = 3):
        # Dense Retrieval
        dense_results = self.vector_store.similarity_search(query, k=top_k)
        
        # Sparse Retrieval
        tokenized_query = query.lower().split()
        bm25_scores = self.bm25.get_scores(tokenized_query)
        top_bm25_idx = sorted(range(len(bm25_scores)), key=lambda i: bm25_scores[i], reverse=True)[:top_k]
        sparse_results = [self.documents[i] for i in top_bm25_idx]
        
        # Combine & Simple Deduplication Rerank
        combined = {doc.page_content if hasattr(doc, 'page_content') else f"{doc['id']} - {doc['name']}: {doc['desc']}": 1 for doc in dense_results}
        for doc in sparse_results:
            key = f"{doc['id']} - {doc['name']}: {doc['desc']}"
            combined[key] = combined.get(key, 0) + 1
            
        # Return top scoring combined items
        sorted_results = sorted(combined.items(), key=lambda x: x[1], reverse=True)
        return [res[0] for res in sorted_results[:top_k]]

if __name__ == "__main__":
    kb = ThreatKnowledgeBase()
    results = kb.hybrid_search("cmd execution and script running")
    print("Hybrid Search Results:\n", json.dumps(results, indent=2))