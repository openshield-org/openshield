"""Shared pytest fixtures for the OpenShield test suite."""

collect_ignore = ["smoke_test.py"]

import secrets
import time

import pytest

from tests.helpers.mock_azure import MockAzureClient

_TEST_JWT_SECRET = secrets.token_urlsafe(32)


@pytest.fixture
def app():
    from api.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    application.config["JWT_SECRET"] = _TEST_JWT_SECRET
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers():
    import jwt
    payload = {
        "sub": "test-user",
        "role": "admin",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, _TEST_JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture
def mock_azure() -> MockAzureClient:
    """Return a clean MockAzureClient with no resources configured."""
    return MockAzureClient()


@pytest.fixture
def subscription_id() -> str:
    """Return a fake Azure subscription ID for use in scan() calls."""
    return "00000000-0000-0000-0000-000000000001"
