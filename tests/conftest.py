import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from app import create_app
from app.extensions import db
from config import TestConfig


@pytest.fixture
def app():
    app = create_app(TestConfig)
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def mock_hibp_check(monkeypatch):
    """
    Prevent tests from making real network calls to the Have I Been Pwned
    API. By default, every password is treated as "not breached" (0), so
    existing tests that use realistic-looking passwords like
    "Str0ng!Passw0rd" keep passing without depending on live network
    access or on whether that exact string happens to appear in a real
    breach dump.

    Individual tests that specifically want to exercise the "this password
    IS breached" path can override this within the test itself, e.g.:

        def test_rejects_breached_password(client, monkeypatch):
            monkeypatch.setattr(
                "app.security.password_validator.check_pwned", lambda pw: 12345
            )
            ...
    """
    monkeypatch.setattr("app.security.password_validator.check_pwned", lambda password: 0)


def register(client, username="alice", email="alice@example.com", password="Str0ng!Passw0rd"):
    return client.post("/api/auth/register", json={
        "username": username, "email": email, "password": password
    })


def login(client, username="alice", password="Str0ng!Passw0rd"):
    return client.post("/api/auth/login", json={"username": username, "password": password})