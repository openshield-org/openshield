"""Regression tests for the RAG dependency and embedding configuration."""

from pathlib import Path

import pytest


def test_vulnerable_transformer_stack_is_not_installed():
    requirements = Path("requirements.txt").read_text(encoding="utf-8").lower()

    assert "sentence-transformers" not in requirements
    assert "transformers" not in requirements


def test_chromadb_not_in_core_requirements():
    requirements = Path("requirements.txt").read_text(encoding="utf-8").lower()

    assert "chromadb" not in requirements, (
        "chromadb must not appear in requirements.txt (CVE-2026-45830, CVE-2026-45833); "
        "use requirements-ai.txt for the optional RAG install"
    )


def test_chroma_default_embedding_uses_onnx_runtime():
    pytest.importorskip(
        "chromadb",
        exc_type=ImportError,
        reason="chromadb not installed (optional RAG dependency); skipping",
    )
    from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

    embedding_function = DefaultEmbeddingFunction()

    assert embedding_function.__class__.__name__ == "ONNXMiniLM_L6_V2"
