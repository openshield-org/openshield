"""Build the OpenShield knowledge base vector store for RAG AI insights"""

import logging
import os
import sys
from pathlib import Path

# Disable ChromaDB telemetry to prevent errors and improve performance on low-RAM machines
os.environ["ANONYMIZED_TELEMETRY"] = "False"

try:
    import chromadb
except ImportError:
    chromadb = None

# Add project root to path for imports
sys.path.append(os.getcwd())

from ai.loader import load_all_documents
from ai.chunker import chunk_documents

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORSTORE_DIR = REPO_ROOT / "ai" / "vectorstore"
COLLECTION_NAME = "openshield"


def build_vectorstore():
    if chromadb is None:
        raise RuntimeError("chromadb is not installed. Install it with 'pip install chromadb'.")

    # 1. Load and chunk documents FIRST (if this fails, existing DB is untouched)
    documents = load_all_documents()
    if not documents:
        raise RuntimeError("No documents found to embed. Check repo paths.")

    chunks = chunk_documents(documents)
    logger.info("Created %d chunks from %d source documents", len(chunks), len(documents))

    # 2. Initialize client
    VECTORSTORE_DIR.mkdir(parents=True, exist_ok=True)
    from chromadb.config import Settings

    client = chromadb.PersistentClient(path=str(VECTORSTORE_DIR), settings=Settings(anonymized_telemetry=False))

    # 3. Create a temporary collection for safe building
    temp_name = f"{COLLECTION_NAME}_temp"
    try:
        client.delete_collection(temp_name)
    except Exception:
        pass
    collection = client.create_collection(temp_name)

    # 4. Add to vector store in batches to prevent memory spikes
    batch_size = 50  # Small batch size for 8GB RAM machines
    for i in range(0, len(chunks), batch_size):
        batch = chunks[i : i + batch_size]

        collection.add(
            ids=[c["id"] for c in batch],
            documents=[c["content"] for c in batch],
            metadatas=[c["metadata"] for c in batch],
        )
        print(f"  Progress: {min(i + batch_size, len(chunks))}/{len(chunks)} chunks embedded...")

    # 5. Atomic Swap: Delete main and rename temp to main
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass

    collection.modify(name=COLLECTION_NAME)

    logger.info("Successfully rebuilt vector store '%s' with %d chunks.", COLLECTION_NAME, len(chunks))
    return len(chunks)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        count = build_vectorstore()
        print(f"Done. Vector store built with {count} chunks at {VECTORSTORE_DIR}")
    except Exception as exc:
        print(f"Error building vector store: {exc}")
        sys.exit(1)
