"""Tests for environment-aware JWT secret resolution in create_app()."""

import secrets

import pytest

from api.app import _INSECURE_JWT_DEFAULT, _MIN_JWT_SECRET_LENGTH, _resolve_jwt_secret, create_app


def _clear_jwt_env(monkeypatch):
    """Remove all env vars that influence JWT resolution."""
    for key in ("OPENSHIELD_ENV", "RENDER", "FLASK_DEBUG", "JWT_SECRET"):
        monkeypatch.delenv(key, raising=False)


# ── _resolve_jwt_secret — development / unspecified paths ────────────────────


def test_unspecified_env_allows_default(monkeypatch):
    """No env vars → permissive path; returns the hardcoded default."""
    _clear_jwt_env(monkeypatch)
    assert _resolve_jwt_secret() == _INSECURE_JWT_DEFAULT


def test_development_env_allows_default(monkeypatch):
    """OPENSHIELD_ENV=development + no JWT_SECRET → returns default."""
    _clear_jwt_env(monkeypatch)
    monkeypatch.setenv("OPENSHIELD_ENV", "development")
    assert _resolve_jwt_secret() == _INSECURE_JWT_DEFAULT


def test_flask_debug_allows_default(monkeypatch):
    """FLASK_DEBUG=true → treated as development; default secret returned."""
    _clear_jwt_env(monkeypatch)
    monkeypatch.setenv("FLASK_DEBUG", "true")
    assert _resolve_jwt_secret() == _INSECURE_JWT_DEFAULT


def test_custom_secret_in_dev(monkeypatch):
    """A custom (short) JWT_SECRET is accepted as-is in development mode."""
    _clear_jwt_env(monkeypatch)
    monkeypatch.setenv("OPENSHIELD_ENV", "development")
    monkeypatch.setenv("JWT_SECRET", "short-but-fine-in-dev")
    assert _resolve_jwt_secret() == "short-but-fine-in-dev"


# ── _resolve_jwt_secret — production fail-closed paths ───────────────────────


def test_production_missing_secret_raises(monkeypatch):
    """OPENSHIELD_ENV=production + no JWT_SECRET → RuntimeError."""
    _clear_jwt_env(monkeypatch)
    monkeypatch.setenv("OPENSHIELD_ENV", "production")
    with pytest.raises(RuntimeError, match="JWT_SECRET is not set"):
        _resolve_jwt_secret()


def test_production_default_secret_raises(monkeypatch):
    """OPENSHIELD_ENV=production + default secret → RuntimeError."""
    _clear_jwt_env(monkeypatch)
    monkeypatch.setenv("OPENSHIELD_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", _INSECURE_JWT_DEFAULT)
    with pytest.raises(RuntimeError, match="insecure default"):
        _resolve_jwt_secret()


def test_production_short_secret_raises(monkeypatch):
    """OPENSHIELD_ENV=production + 31-char secret → RuntimeError."""
    _clear_jwt_env(monkeypatch)
    monkeypatch.setenv("OPENSHIELD_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", "a" * (_MIN_JWT_SECRET_LENGTH - 1))
    with pytest.raises(RuntimeError, match=f"at least {_MIN_JWT_SECRET_LENGTH} characters"):
        _resolve_jwt_secret()


def test_render_missing_secret_raises(monkeypatch):
    """RENDER=true + no JWT_SECRET → RuntimeError."""
    _clear_jwt_env(monkeypatch)
    monkeypatch.setenv("RENDER", "true")
    with pytest.raises(RuntimeError, match="JWT_SECRET is not set"):
        _resolve_jwt_secret()


def test_render_default_secret_raises(monkeypatch):
    """RENDER=true + default secret → RuntimeError."""
    _clear_jwt_env(monkeypatch)
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("JWT_SECRET", _INSECURE_JWT_DEFAULT)
    with pytest.raises(RuntimeError, match="insecure default"):
        _resolve_jwt_secret()


def test_production_strong_secret_accepted(monkeypatch):
    """OPENSHIELD_ENV=production + 32-char secret → returned as-is."""
    _clear_jwt_env(monkeypatch)
    secret = secrets.token_urlsafe(32)
    monkeypatch.setenv("OPENSHIELD_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", secret)
    assert _resolve_jwt_secret() == secret


def test_production_exactly_32_chars_accepted(monkeypatch):
    """Exactly 32 characters meets the minimum and is accepted."""
    _clear_jwt_env(monkeypatch)
    secret = "a" * _MIN_JWT_SECRET_LENGTH
    monkeypatch.setenv("OPENSHIELD_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", secret)
    assert _resolve_jwt_secret() == secret


def test_render_strong_secret_accepted(monkeypatch):
    """RENDER=true + strong secret → returned as-is."""
    _clear_jwt_env(monkeypatch)
    secret = secrets.token_urlsafe(32)
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("JWT_SECRET", secret)
    assert _resolve_jwt_secret() == secret


# ── create_app() integration — verifies wiring end-to-end ────────────────────


def test_create_app_production_uses_strong_secret(monkeypatch):
    """create_app() in production mode wires the config correctly."""
    secret = secrets.token_urlsafe(32)
    monkeypatch.setenv("OPENSHIELD_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", secret)
    app = create_app()
    assert app.config["JWT_SECRET"] == secret


def test_create_app_development_starts_without_secret(monkeypatch):
    """create_app() in development mode starts without a JWT_SECRET set."""
    monkeypatch.setenv("OPENSHIELD_ENV", "development")
    monkeypatch.delenv("JWT_SECRET", raising=False)
    app = create_app()
    assert app.config["JWT_SECRET"] == _INSECURE_JWT_DEFAULT
