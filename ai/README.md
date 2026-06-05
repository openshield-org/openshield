# OpenShield RAG Pipeline

Document loader and chunker for OpenShield rules and compliance frameworks.
Loads all scanner rules and CIS, NIST, ISO 27001 and SOC2 controls
into structured documents for the RAG vector store.

## Files

- `ai/loader.py` — loads OpenShield rules and compliance frameworks as structured documents
- `ai/chunker.py` — splits documents into overlapping chunks for embedding
- `ai/embed.py` — builds the ChromaDB vector store (from PR 97)
- `ai/retriever.py` — queries the vector store (from PR 97)

## Vector Store

The vector store is persisted at `ai/vectorstore/` using ChromaDB.

## How loader.py works

Reads all `scanner/rules/az_*.py` files and extracts:
- Rule ID, name, severity, category
- Description and remediation text

Also reads all four compliance framework JSON files:
- CIS Azure Benchmark
- NIST CSF
- ISO 27001
- SOC2

## How chunker.py works

Splits documents into 512-character overlapping chunks with 64-character
overlap. Tries to split on newlines to avoid breaking mid-sentence.
Each chunk inherits the metadata of its parent document.
