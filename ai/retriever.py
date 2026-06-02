"""Retrieve relevant OpenShield knowledge from the vector store for RAG."""

import logging
from pathlib import Path

try:
    import chromadb
except ImportError:
    chromadb = None

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORSTORE_DIR = REPO_ROOT / "ai" / "vectorstore"
COLLECTION_NAME = "openshield"


class VectorStoreNotBuilt(RuntimeError):
    """Raised when the vector store is missing or chromadb is unavailable."""


def _get_collection():
    if chromadb is None:
        raise VectorStoreNotBuilt(
            "chromadb is not installed. Install it with 'pip install chromadb'."
        )
    if not VECTORSTORE_DIR.exists():
        raise VectorStoreNotBuilt(
            "Vector store not found. Run 'python ai/embed.py' first."
        )
    client = chromadb.PersistentClient(path=str(VECTORSTORE_DIR))
    try:
        return client.get_collection(COLLECTION_NAME)
    except Exception as exc:
        raise VectorStoreNotBuilt(
            "Vector store collection missing. Run 'python ai/embed.py' first."
        ) from exc


def retrieve(query, n_results=5):
    """Return the most relevant knowledge chunks for a query.

    Each result is a dict with 'text' and 'source'.
    """
    collection = _get_collection()
    results = collection.query(query_texts=[query], n_results=n_results)
    documents = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]
    chunks = []
    for text, meta in zip(documents, metadatas):
        chunks.append({"text": text, "source": (meta or {}).get("source", "")})
    return chunks
