"""Retrieve relevant OpenShield knowledge using BM25 scoring."""

import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORSTORE_DIR = REPO_ROOT / "ai" / "vectorstore"
INDEX_PATH = VECTORSTORE_DIR / "bm25_index.json"

_BM25_K1 = 1.5
_BM25_B = 0.75

_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "but",
        "by",
        "for",
        "from",
        "had",
        "has",
        "have",
        "if",
        "in",
        "is",
        "it",
        "no",
        "not",
        "of",
        "on",
        "or",
        "so",
        "that",
        "the",
        "this",
        "to",
        "was",
        "were",
        "with",
    }
)


class VectorStoreNotBuilt(RuntimeError):
    """Raised when the BM25 index is missing or unreadable."""


def _tokenize(text: str) -> list:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 2 and t not in _STOPWORDS]


def _load_index() -> dict:
    if not INDEX_PATH.exists():
        raise VectorStoreNotBuilt("BM25 index not found. Run 'python ai/embed.py' first.")
    try:
        return json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise VectorStoreNotBuilt(f"BM25 index unreadable: {exc}") from exc


def _bm25_score(query_terms: list, doc_terms: dict, dl: int, avg_dl: float, idf: dict) -> float:
    score = 0.0
    for term in query_terms:
        tf = doc_terms.get(term, 0)
        if tf == 0:
            continue
        norm = tf * (_BM25_K1 + 1) / (tf + _BM25_K1 * (1 - _BM25_B + _BM25_B * dl / avg_dl))
        score += idf.get(term, 0.0) * norm
    return score


def retrieve(query: str, n_results: int = 5) -> list:
    """Return the most relevant knowledge chunks for a query.

    Each result is a dict with 'text', 'source', and 'source_meta'.
    """
    index = _load_index()
    avg_dl = index["avg_dl"]
    idf = index["idf"]
    query_terms = _tokenize(query)

    scored = []
    for chunk in index["chunks"]:
        score = _bm25_score(query_terms, chunk["terms"], chunk["dl"], avg_dl, idf)
        if score > 0:
            scored.append((score, chunk))

    scored.sort(key=lambda x: x[0], reverse=True)
    top = [chunk for _, chunk in scored[:n_results]]

    results = []
    for chunk in top:
        meta = chunk.get("metadata") or {}
        source_type = meta.get("source", "unknown")

        if source_type == "openShield_rule":
            source_id = meta.get("rule_id", "Rule")
            source_resource = meta.get("rule_name", "")
        elif source_type == "claude_red_skill":
            source_id = meta.get("skill_name", "Skill")
            source_resource = ""
        elif source_type == "compliance_framework":
            source_id = f"{meta.get('framework', 'Compliance')} {meta.get('control_id', '')}".strip()
            source_resource = meta.get("control_name", "")
        else:
            source_id = "General"
            source_resource = ""

        results.append(
            {
                "text": chunk["content"],
                "source": source_id,
                "source_meta": {
                    "id": source_id,
                    "type": source_type,
                    "resource": source_resource,
                    "file": meta.get("file", ""),
                },
            }
        )
    return results
