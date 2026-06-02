"""AI provider abstraction layer supporting Anthropic, Groq and Gemini."""

import logging
import requests

logger = logging.getLogger(__name__)

PROVIDERS = ("anthropic", "groq", "gemini")

DEFAULT_MODELS = {
    "anthropic": "claude-3-5-haiku-20241022",
    "groq": "llama-3.1-8b-instant",
    "gemini": "gemini-1.5-flash",
}


def get_completion(
    provider: str, api_key: str, prompt: str, model: str = None
) -> str:
    provider = provider.lower().strip()
    if provider not in PROVIDERS:
        raise ValueError(
            f"Unsupported provider '{provider}'. Choose from: {', '.join(PROVIDERS)}"
        )
    if not api_key or not api_key.strip():
        raise ValueError("api_key is required and cannot be empty")

    resolved_model = model or DEFAULT_MODELS[provider]

    if provider == "anthropic":
        return _anthropic(api_key, prompt, resolved_model)
    if provider == "groq":
        return _groq(api_key, prompt, resolved_model)
    return _gemini(api_key, prompt, resolved_model)


def _anthropic(api_key: str, prompt: str, model: str) -> str:
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
        if resp.status_code == 401:
            raise ValueError("Invalid Anthropic API key")
        if resp.status_code == 429:
            raise RuntimeError("Anthropic rate limit reached, try again later")
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]
    except (ValueError, RuntimeError):
        raise
    except requests.exceptions.RequestException as exc:
        logger.error("Anthropic request failed: %s", exc)
        raise RuntimeError(f"Anthropic request failed: {exc}") from exc


def _groq(api_key: str, prompt: str, model: str) -> str:
    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
            },
            timeout=30,
        )
        if resp.status_code == 401:
            raise ValueError("Invalid Groq API key")
        if resp.status_code == 429:
            raise RuntimeError("Groq rate limit reached, try again later")
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except (ValueError, RuntimeError):
        raise
    except requests.exceptions.RequestException as exc:
        logger.error("Groq request failed: %s", exc)
        raise RuntimeError(f"Groq request failed: {exc}") from exc


def _gemini(api_key: str, prompt: str, model: str) -> str:
    try:
        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            params={"key": api_key},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=30,
        )
        if resp.status_code == 400 and "API_KEY_INVALID" in resp.text:
            raise ValueError("Invalid Gemini API key")
        if resp.status_code == 429:
            raise RuntimeError("Gemini rate limit reached, try again later")
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    except (ValueError, RuntimeError):
        raise
    except requests.exceptions.RequestException as exc:
        logger.error("Gemini request failed: %s", exc)
        raise RuntimeError(f"Gemini request failed: {exc}") from exc
