"""Regression tests for the RAG dependency and embedding configuration."""

from pathlib import Path


def test_vulnerable_transformer_stack_is_not_installed():
    requirements = Path("requirements.txt").read_text(encoding="utf-8").lower()

    assert "sentence-transformers" not in requirements
    assert "transformers" not in requirements


def test_chromadb_absent_from_all_requirements():
    for req_file in Path(".").glob("requirements*.txt"):
        content = req_file.read_text(encoding="utf-8").lower()
        assert "chromadb" not in content, (
            f"chromadb must not appear in {req_file} "
            "(CVE-2026-45830 tenant-isolation bypass, CVE-2026-45833 RCE); "
            "the RAG pipeline now uses a pure-Python BM25 index with no C extensions"
        )


def test_requirements_ai_txt_does_not_exist():
    assert not Path("requirements-ai.txt").exists(), (
        "requirements-ai.txt must be deleted; chromadb has been replaced by the "
        "pure-Python BM25 index in ai/embed.py and ai/retriever.py"
    )


def test_bm25_retriever_tokenizer():
    from ai.retriever import _tokenize

    tokens = _tokenize("Azure Storage Account immutability policy")
    assert "azure" in tokens
    assert "storage" in tokens
    assert "immutability" in tokens
    assert "policy" in tokens
    # stopwords filtered
    assert "the" not in tokens
    assert "and" not in tokens


def test_bm25_score_zero_for_no_overlap():
    from ai.retriever import _bm25_score

    score = _bm25_score(["kubernetes"], {"azure": 2, "storage": 1}, dl=3, avg_dl=3.0, idf={"azure": 1.0})
    assert score == 0.0


def test_bm25_score_positive_for_matching_term():
    from ai.retriever import _bm25_score

    idf = {"storage": 2.0}
    score = _bm25_score(["storage"], {"storage": 3}, dl=5, avg_dl=5.0, idf=idf)
    assert score > 0.0


def test_bm25_score_higher_for_more_matches():
    from ai.retriever import _bm25_score

    idf = {"storage": 1.5, "immutable": 1.2}
    score_one = _bm25_score(["storage"], {"storage": 2, "immutable": 1}, dl=3, avg_dl=3.0, idf=idf)
    score_two = _bm25_score(["storage", "immutable"], {"storage": 2, "immutable": 1}, dl=3, avg_dl=3.0, idf=idf)
    assert score_two > score_one


def test_numpy_not_required():
    requirements = Path("requirements.txt").read_text(encoding="utf-8").lower()
    assert "numpy" not in requirements, "numpy must not be in requirements.txt; BM25 retrieval uses only stdlib math"
