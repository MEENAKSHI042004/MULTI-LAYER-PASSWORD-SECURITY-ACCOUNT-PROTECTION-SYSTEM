"""Deployment-related behaviour: trusted-proxy handling and DB URL normalisation."""

import os
import subprocess
import sys

from app import create_app
from app.routes.auth import _client_ip
from config import TestConfig

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class OneProxyConfig(TestConfig):
    TRUST_PROXY_HOPS = 1


def _app_with_ip_route(config):
    app = create_app(config)

    @app.route("/_ip")
    def _ip():
        return _client_ip()

    return app


def test_forged_forwarded_for_is_ignored_by_default():
    """With no trusted proxy configured, a client can't choose its own logged IP."""
    app = _app_with_ip_route(TestConfig)
    resp = app.test_client().get(
        "/_ip",
        headers={"X-Forwarded-For": "6.6.6.6"},
        environ_base={"REMOTE_ADDR": "1.2.3.4"},
    )
    assert resp.get_data(as_text=True) == "1.2.3.4"


def test_one_trusted_proxy_exposes_real_client_ip():
    """Behind one proxy, the address the proxy appended is the real client."""
    app = _app_with_ip_route(OneProxyConfig)
    resp = app.test_client().get(
        "/_ip",
        headers={"X-Forwarded-For": "9.9.9.9"},
        environ_base={"REMOTE_ADDR": "10.0.0.1"},  # the proxy
    )
    assert resp.get_data(as_text=True) == "9.9.9.9"


def test_one_trusted_proxy_ignores_client_supplied_prefix():
    """A client-forged leading entry must not be trusted past the real hop count."""
    app = _app_with_ip_route(OneProxyConfig)
    resp = app.test_client().get(
        "/_ip",
        # 6.6.6.6 was forged by the client; the proxy appended the true 9.9.9.9
        headers={"X-Forwarded-For": "6.6.6.6, 9.9.9.9"},
        environ_base={"REMOTE_ADDR": "10.0.0.1"},
    )
    assert resp.get_data(as_text=True) == "9.9.9.9"


def _db_uri_for(env_value):
    code = (
        "import os; os.environ['DATABASE_URL']=%r; import config; "
        "print(config.Config.SQLALCHEMY_DATABASE_URI)" % env_value
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True
    )
    return out.stdout.strip().splitlines()[-1]


def test_postgres_scheme_is_normalised():
    assert _db_uri_for("postgres://u:p@host/db") == "postgresql://u:p@host/db"


def test_postgresql_scheme_is_left_alone():
    assert _db_uri_for("postgresql://u:p@host/db") == "postgresql://u:p@host/db"
