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


def register(client, username="alice", email="alice@example.com", password="Str0ng!Passw0rd"):
    return client.post("/api/auth/register", json={
        "username": username, "email": email, "password": password
    })


def login(client, username="alice", password="Str0ng!Passw0rd"):
    return client.post("/api/auth/login", json={"username": username, "password": password})
