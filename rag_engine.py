import json
from pathlib import Path

from langchain_community.vectorstores import Chroma
from langchain_ollama import OllamaEmbeddings
from rank_bm25 import BM25Okapi  # type: ignore[import-untyped]


class ThreatKnowledgeBase:
    def __init__(self, mitre_data_path: str = "mitre_attack.json"):
        # 1. Initialize Local Embeddings
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large")

        # 2. Load MITRE ATT&CK technique data (falls back to a tiny built-in
        #    sample if the file is missing, so the class still works standalone)
        self.documents = self._load_documents(mitre_data_path)
        self.texts = [self._format(d) for d in self.documents]

        # 3. Build Dense Index (ChromaDB)
        self.vector_store = Chroma.from_texts(
            texts=self.texts,
            embedding=self.embeddings,
            collection_name="mitre_attack",
        )

        # 4. Build Sparse Index (BM25)
        tokenized_corpus = [text.lower().split() for text in self.texts]
        self.bm25 = BM25Okapi(tokenized_corpus)

    @staticmethod
    def _format(doc: dict) -> str:
        return f"{doc['id']} - {doc['name']}: {doc['desc']}"

    @staticmethod
    def _load_documents(path: str) -> list[dict]:
        # Try the path as given, then relative to this file's directory,
        # so it loads regardless of the caller's current working directory.
        for candidate in (Path(path), Path(__file__).parent / path):
            try:
                with open(candidate) as f:
                    data = json.load(f)
                if data:
                    return data
            except (FileNotFoundError, json.JSONDecodeError):
                continue
        # Fallback sample, used only if mitre_data_path isn't found/valid
        return [
            {"id": "T1059.001", "name": "PowerShell", "desc": "Adversaries may use PowerShell to perform actions like command execution and script running."},
            {"id": "T1053.005", "name": "Scheduled Task", "desc": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or persistent execution."},
            {"id": "T1003.001", "name": "LSASS Memory", "desc": "Adversaries may attempt to access credentials by dumping LSASS process memory."},
        ]

    def dense_search(self, query: str, top_k: int = 3) -> list[str]:
        """Pure dense (embedding similarity) search — exposed standalone for evaluation."""
        results = self.vector_store.similarity_search(query, k=top_k)
        return [r.page_content for r in results]

    def sparse_search(self, query: str, top_k: int = 3) -> list[str]:
        """Pure sparse (BM25 keyword) search — exposed standalone for evaluation."""
        tokenized_query = query.lower().split()
        scores = self.bm25.get_scores(tokenized_query)
        top_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:top_k]
        return [self.texts[i] for i in top_idx]

    def hybrid_search(self, query: str, top_k: int = 3, rrf_k: int = 60) -> list[str]:
        """Hybrid dense + sparse search, merged with Reciprocal Rank Fusion (RRF).

        RRF scores each document by 1/(rrf_k + rank) in each ranked list and
        sums across lists, so a document ranked highly by *either* method
        (and especially by both) rises to the top — a standard, parameter-light
        alternative to a trained cross-encoder reranker.
        """
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


if __name__ == "__main__":
    kb = ThreatKnowledgeBase()
    results = kb.hybrid_search("cmd execution and script running")
    print("Hybrid Search Results:\n", json.dumps(results, indent=2))
