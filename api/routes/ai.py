"""AI insights route: executive summary and prioritised remediation plan."""

import logging

from flask import Blueprint, jsonify, request

from api.services.ai_provider import PROVIDERS as SUPPORTED_PROVIDERS
from api.services.ai_provider import get_completion

ai_bp = Blueprint("ai", __name__, url_prefix="/api/ai")
logger = logging.getLogger(__name__)

_SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1,
    "INFO": 1,
}


def severity_rank(finding: dict) -> int:
    return _SEVERITY_RANK.get(str(finding.get("severity", "")).upper(), 0)


def _build_summary_prompt(findings: list) -> str:
    lines = []
    for f in findings:
        title = f.get("title") or f.get("rule_name") or "Untitled"
        lines.append(
            f"- [{f.get('severity', 'UNKNOWN')}] {title}: {f.get('description', 'No description provided.')}"
        )
    findings_text = "\n".join(lines)
    return (
        "You are a security advisor writing for a non-technical executive audience.\n"
        "Based on the following cloud security findings, write a concise executive summary.\n"
        "Avoid technical jargon. Mention the overall security risk level and likely business or operational impact.\n"
        "Do not invent findings. If information is missing, say so clearly.\n\n"
        f"Findings:\n{findings_text}\n\n"
        "Executive Summary:"
    )


def _build_question_prompt(sorted_findings: list, question: str) -> str:
    lines = []
    for f in sorted_findings:
        rule_id = f.get("rule_id", "")
        title = f.get("title") or f.get("rule_name") or "Untitled"
        severity = f.get("severity", "UNKNOWN")
        description = f.get("description", "No description provided.")
        remediation = f.get("remediation", "No remediation detail provided.")
        label = f"{rule_id} — {title}" if rule_id else title
        lines.append(
            f"- [{severity}] {label}: {description} Remediation: {remediation}"
        )
    findings_text = "\n".join(lines)
    return (
        "You are a cloud security assistant.\n"
        "Answer the user's question using only the scan findings provided below.\n"
        "Do not invent facts or assume scan results that are not listed.\n"
        "Prioritise high severity, exploitable, and compliance-impacting findings, "
        "and consider remediation urgency.\n"
        "Be concise but useful. If the findings are insufficient to answer "
        "confidently, say what evidence is missing.\n\n"
        f"Question: {question}\n\n"
        f"Findings (severity order):\n{findings_text}\n\n"
        "Answer:"
    )


def _build_remediation_prompt(sorted_findings: list) -> str:
    lines = []
    for f in sorted_findings:
        rule_id = f.get("rule_id", "")
        title = f.get("title") or f.get("rule_name") or "Untitled"
        severity = f.get("severity", "UNKNOWN")
        remediation = f.get("remediation", "No remediation detail provided.")
        label = f"{rule_id} — {title}" if rule_id else title
        lines.append(f"- [{severity}] {label}: {remediation}")
    findings_text = "\n".join(lines)
    return (
        "You are a cloud security engineer writing a remediation plan.\n"
        "The findings below are already sorted by severity (Critical first, then High, Medium, Low, Informational).\n"
        "For each finding, provide practical, actionable fix steps.\n"
        "Reference the rule ID and title where available.\n"
        "Do not invent findings. If a finding lacks remediation detail, state what information is missing.\n\n"
        f"Findings (severity order):\n{findings_text}\n\n"
        "Prioritised Remediation Plan:"
    )


@ai_bp.post("/insights")
def insights():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    provider = str(data.get("provider") or "").strip().lower()
    api_key = str(data.get("api_key") or "").strip()
    findings = data.get("findings")
    question = str(data.get("question") or "").strip()

    if not provider:
        return jsonify({"error": "Missing required field: provider"}), 400
    if provider not in SUPPORTED_PROVIDERS:
        return jsonify({"error": f"Unsupported provider: {provider}"}), 400
    if not api_key:
        return jsonify({"error": "Missing required field: api_key"}), 400
    if findings is None:
        return jsonify({"error": "Missing required field: findings"}), 400
    if not isinstance(findings, list):
        return jsonify({"error": "findings must be a list"}), 400
    if len(findings) == 0:
        return jsonify({"error": "findings must not be empty"}), 400

    sorted_findings = sorted(findings, key=severity_rank, reverse=True)

    summary_prompt = _build_summary_prompt(sorted_findings)
    remediation_prompt = _build_remediation_prompt(sorted_findings)

    try:
        executive_summary = get_completion(provider, api_key, summary_prompt)
        remediation_plan = get_completion(provider, api_key, remediation_prompt)
        answer = None
        if question:
            question_prompt = _build_question_prompt(sorted_findings, question)
            answer = get_completion(provider, api_key, question_prompt)
    except Exception:
        logger.warning("AI provider request failed for provider=%s", provider)
        return jsonify({"error": "AI provider request failed"}), 502

    response = {
        "executive_summary": executive_summary,
        "remediation_plan": remediation_plan,
    }
    if question:
        response["answer"] = answer

    return jsonify(response)
