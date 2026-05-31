"""Build the OpenShield knowledge base vector store for RAG AI insights"""


import importlib.util
import json
import logging
from pathlib import Path

import chromadb

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "scanner" / "rules"
FRAMEWORKS_DIR = REPO_ROOT / "compliance" / "frameworks"
SKILLS_DIR = REPO_ROOT / "ai" / "knowledge" / "skills"
VECTORSTORE_DIR = REPO_ROOT / "ai" / "vectorstore"
COLLECTION_NAME = "openshield"


def _load_rule_module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _collect_skill_documents():
    documents = []
    if not SKILLS_DIR.exists():
        logger.warning("Skills directory not found, skipping: %s", SKILLS_DIR)
        return documents
    for path in sorted(SKILLS_DIR.rglob("SKILL.md")):
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as exc:
            logger.warning("Skipping %s: %s", path.name, exc)
            continue
        if not text.strip():
            continue
        skill_name = path.parent.name
        documents.append({
            "id": f"skill-{skill_name}",
            "text": text,
            "source": skill_name,
            "type": "skill",
        })
    return documents


def _collect_rule_documents():
    documents = []
    for path in sorted(RULES_DIR.glob("az_*.py")):
        try:
            module = _load_rule_module(path)
        except Exception as exc:
            logger.warning("Skipping %s: %s", path.name, exc)
            continue
        rule_id = getattr(module, "RULE_ID", None)
        if not rule_id:
            continue
        text = (
            f"OpenShield rule {rule_id}: {getattr(module, 'RULE_NAME', '')}\n"
            f"Category: {getattr(module, 'CATEGORY', '')}\n"
            f"Severity: {getattr(module, 'SEVERITY', '')}\n"
            f"Description: {getattr(module, 'DESCRIPTION', '')}\n"
            f"Remediation: {getattr(module, 'REMEDIATION', '')}"
        )
        documents.append({
            "id": f"rule-{rule_id}",
            "text": text,
            "source": rule_id,
            "type": "rule",
        })
    return documents


def _collect_compliance_documents():
    documents = []
    for path in sorted(FRAMEWORKS_DIR.glob("*.json")):
        framework = path.stem
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Skipping %s: %s", path.name, exc)
            continue
        for control_id, control in data.get("controls", {}).items():
            description = control.get("description", "")
            if not description:
                continue
            text = (
                f"{framework} control {control_id}: "
                f"{control.get('control_name', '')}\n{description}"
            )
            documents.append({
                "id": f"{framework}-{control_id}",
                "text": text,
                "source": f"{framework} {control_id}",
                "type": "control",
            })
    return documents


def build_vectorstore():
    VECTORSTORE_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(VECTORSTORE_DIR))

    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass
    collection = client.create_collection(COLLECTION_NAME)

    documents = (
        _collect_skill_documents()
        + _collect_rule_documents()
        + _collect_compliance_documents()
    )
    if not documents:
        raise RuntimeError("No documents found to embed. Check repo paths.")

    collection.add(
        ids=[d["id"] for d in documents],
        documents=[d["text"] for d in documents],
        metadatas=[
            {"source": d["source"], "type": d["type"]} for d in documents
        ],
    )
    logger.info(
        "Embedded %d documents into '%s'.", len(documents), COLLECTION_NAME
    )
    return len(documents)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    count = build_vectorstore()
    print(f"Done. Vector store built with {count} documents at {VECTORSTORE_DIR}")
