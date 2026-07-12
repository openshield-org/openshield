"""Regression tests for the RAG dependency and embedding configuration."""

from pathlib import Path


def test_vulnerable_transformer_stack_is_not_installed():
    requirements = Path("requirements.txt").read_text(encoding="utf-8").lower()

    assert "sentence-transformers" not in requirements
    assert "transformers" not in requirements


def test_chroma_default_embedding_uses_onnx_runtime():
    from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

    embedding_function = DefaultEmbeddingFunction()

    assert embedding_function.__class__.__name__ == "ONNXMiniLM_L6_V2"
