"""AI insights routes: RAG grounded summary, prioritisation and Q&A."""

import json
import logging

from flask import Blueprint, jsonify, request

from api.services.ai_provider import get_completion
from ai.retriever import retrieve, VectorStoreNotBuilt

ai_bp = Blueprint("ai", __name__)
logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def _findings_to_text(findings):
    ordered = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(str(f.get("severity", "")).upper(), 4),
    )
    lines = []
    for i, f in enumerate(ordered, 1):
        lines.append(
            f"{i}. [{f.get('severity', 'UNKNOWN')}] "
            f"{f.get('rule_name', 'Unknown')} on "
            f"{f.get('resource_name', 'unknown resource')}: "
            f"{f.get('description', '')}"
        )
    return "\n".join(lines) if lines else "No findings."


def _context_for(query):
    chunks = retrieve(query, n_results=5)
    context = "\n".join(f"- ({c['source']}) {c['text']}" for c in chunks)
    sources = [c["source"] for c in chunks if c["source"]]
    return context, sources


def _read_request():
    body = request.get_json(silent=True)
    if not body:
        return None, (jsonify({"error": "Request body must be JSON"}), 400)
    if not body.get("provider"):
        return None, (jsonify({"error": "provider is required"}), 400)
    if not body.get("api_key"):
        return None, (jsonify({"error": "api_key is required"}), 400)
    return body, None


@ai_bp.post("/api/ai/summary")
def ai_summary():
    body, error = _read_request()
    if error:
        return error
    findings = body.get("findings", [])
    if not isinstance(findings, list):
        return jsonify({"error": "findings must be a list"}), 400

    findings_text = _findings_to_text(findings)
    try:
        context, sources = _context_for(findings_text)
    except VectorStoreNotBuilt as exc:
        return jsonify({"error": str(exc)}), 503

    prompt = (
        "You are a cloud security advisor. Using ONLY the grounded knowledge "
        "below, write a plain English executive summary of the security "
        "posture for a non technical reader. Keep it under 120 words.\n\n"
        f"GROUNDED KNOWLEDGE:\n{context}\n\nFINDINGS:\n{findings_text}"
    )
    try:
        answer = get_completion(
            body["provider"], body["api_key"], prompt, model=body.get("model")
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 502

    return jsonify({
        "summary": answer,
        "sources": sources,
        "provider": body["provider"],
        "model": body.get("model"),
    })


@ai_bp.post("/api/ai/prioritise")
def ai_prioritise():
    body, error = _read_request()
    if error:
        return error
    findings = body.get("findings", [])
    if not isinstance(findings, list):
        return jsonify({"error": "findings must be a list"}), 400

    findings_text = _findings_to_text(findings)
    try:
        context, sources = _context_for(findings_text)
    except VectorStoreNotBuilt as exc:
        return jsonify({"error": str(exc)}), 503

    prompt = (
        "You are a cloud security advisor. Using ONLY the grounded knowledge "
        "below, rank these findings by real world exploitability and business "
        "risk, not just the severity label. Respond with valid JSON only, no "
        "markdown, as a list of objects with fields: priority, rule_name, "
        "resource_name, severity, reason.\n\n"
        f"GROUNDED KNOWLEDGE:\n{context}\n\nFINDINGS:\n{findings_text}"
    )
    try:
        raw = get_completion(
            body["provider"], body["api_key"], prompt, model=body.get("model")
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 502

    try:
        prioritised = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        prioritised = raw

    return jsonify({
        "prioritised_findings": prioritised,
        "sources": sources,
        "provider": body["provider"],
        "model": body.get("model"),
    })


@ai_bp.post("/api/ai/ask")
def ai_ask():
    body, error = _read_request()
    if error:
        return error
    question = body.get("question", "")
    if not question or not question.strip():
        return jsonify({"error": "question is required"}), 400

    try:
        context, sources = _context_for(question)
    except VectorStoreNotBuilt as exc:
        return jsonify({"error": str(exc)}), 503

    findings = body.get("findings", [])
    findings_text = _findings_to_text(findings) if findings else "Not provided."

    prompt = (
        "You are a cloud security advisor. Answer the question using ONLY the "
        "grounded knowledge below. If the answer is not in the knowledge, say "
        "so honestly. Reference specific rule IDs or controls where relevant."
        f"\n\nGROUNDED KNOWLEDGE:\n{context}\n\n"
        f"CURRENT FINDINGS:\n{findings_text}\n\nQUESTION: {question}"
    )
    try:
        answer = get_completion(
            body["provider"], body["api_key"], prompt, model=body.get("model")
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 502

    return jsonify({
        "answer": answer,
        "sources": sources,
        "provider": body["provider"],
        "model": body.get("model"),
    })
