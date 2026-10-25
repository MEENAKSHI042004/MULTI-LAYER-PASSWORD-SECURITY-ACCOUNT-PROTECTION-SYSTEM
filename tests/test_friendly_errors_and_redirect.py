"""
Two demo-safety behaviours:

1. API failures (rate limit, crash) come back as JSON with a human message,
   not HTML -- the front-ends parse JSON, and an HTML body used to surface
   as a vague "Registration failed." with no hint of the real cause.
2. Pages opened via 127.0.0.1 redirect to localhost (passkeys don't work on
   a numeric address), without breaking API/health calls to 127.0.0.1.
"""

from flask import abort

from app import create_app
from config import TestConfig


def _app():
    app = create_app(TestConfig)
    app.config["PROPAGATE_EXCEPTIONS"] = False  # let the 500 handler run

    @app.route("/api/_t429")
    def _t429():
        abort(429)

    @app.route("/api/_t500")
    def _t500():
        raise RuntimeError("boom")

    @app.route("/_page429")
    def _page429():
        abort(429)

    return app


# ---------------------------------------------------------------- JSON errors
def test_api_rate_limit_returns_json_message():
    resp = _app().test_client().get("/api/_t429")
    assert resp.status_code == 429
    assert resp.is_json
    assert "wait" in resp.get_json()["error"].lower()


def test_api_server_error_returns_json_without_leaking_details():
    resp = _app().test_client().get("/api/_t500")
    assert resp.status_code == 500
    assert resp.is_json
    body = resp.get_data(as_text=True)
    assert "boom" not in body and "Traceback" not in body


def test_non_api_rate_limit_keeps_default_page():
    resp = _app().test_client().get("/_page429")
    assert resp.status_code == 429
    assert not resp.is_json


# ------------------------------------------------------------------- redirect
def test_loopback_ip_page_redirects_to_localhost():
    resp = _app().test_client().get("/", base_url="http://127.0.0.1:5000")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "http://localhost:5000/"


def test_redirect_keeps_the_query_string():
    resp = _app().test_client().get("/?next=%2Faccount", base_url="http://127.0.0.1:5000")
    assert resp.headers["Location"] == "http://localhost:5000/?next=%2Faccount"


def test_localhost_is_not_redirected():
    resp = _app().test_client().get("/", base_url="http://localhost:5000")
    assert resp.status_code == 200


def test_health_and_api_on_loopback_ip_are_not_redirected():
    client = _app().test_client()
    assert client.get("/health", base_url="http://127.0.0.1:5000").status_code == 200
    # unauthenticated /me is a 401 from the API itself, not a redirect
    assert client.get("/api/auth/me", base_url="http://127.0.0.1:5000").status_code == 401


def test_non_get_requests_are_never_redirected():
    # a redirect would drop the POST body; API posts to 127.0.0.1 must still work
    resp = _app().test_client().post(
        "/api/auth/login", json={"username": "x", "password": "y"},
        base_url="http://127.0.0.1:5000",
    )
    assert resp.status_code != 302
