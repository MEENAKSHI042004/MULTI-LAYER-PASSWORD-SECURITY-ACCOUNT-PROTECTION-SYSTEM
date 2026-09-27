import base64
from types import SimpleNamespace

from app.extensions import db
from app.models import AuditLog, LoginAttempt, Session, User, WebAuthnCredential
from app.security.jwt_utils import create_webauthn_challenge_token, decode_token
from tests.conftest import login, register


def _authenticated_headers(client):
    register(client)
    response = login(client)
    return {"Authorization": f"Bearer {response.get_json()['access_token']}"}


def _b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def test_webauthn_register_begin_returns_challenge_and_excludes_existing_key(client, app):
    headers = _authenticated_headers(client)
    with app.app_context():
        user = User.query.filter_by(username="alice").first()
        db.session.add(WebAuthnCredential(
            user_id=user.id,
            credential_id=_b64url(b"existing-key"),
            public_key=b"public-key",
            sign_count=0,
        ))
        db.session.commit()

    response = client.post("/api/auth/webauthn/register/begin", headers=headers, json={})

    assert response.status_code == 200
    body = response.get_json()
    with app.app_context():
        challenge_payload = decode_token(body["challenge_token"])
    assert challenge_payload["purpose"] == "webauthn_registration"
    assert challenge_payload["challenge"] == body["options"]["challenge"]
    assert body["options"]["excludeCredentials"][0]["id"] == _b64url(b"existing-key")


def test_webauthn_register_complete_saves_verified_credential(client, app, monkeypatch):
    headers = _authenticated_headers(client)
    begin = client.post("/api/auth/webauthn/register/begin", headers=headers, json={})
    challenge_token = begin.get_json()["challenge_token"]
    verified = SimpleNamespace(
        credential_id=b"new-key",
        credential_public_key=b"verified-public-key",
        sign_count=7,
    )

    def verify_registration_response(**kwargs):
        assert kwargs["expected_rp_id"] == app.config["WEBAUTHN_RP_ID"]
        assert kwargs["expected_origin"] == app.config["WEBAUTHN_ORIGIN"]
        assert kwargs["credential"].raw_id == b"raw-key"
        return verified

    monkeypatch.setattr(
        "app.routes.auth.verify_registration_response", verify_registration_response
    )
    response = client.post(
        "/api/auth/webauthn/register/complete",
        headers=headers,
        json={
            "challenge_token": challenge_token,
            "credential": {
                "id": _b64url(b"raw-key"),
                "rawId": _b64url(b"raw-key"),
                "response": {
                    "clientDataJSON": _b64url(b"client-data"),
                    "attestationObject": _b64url(b"attestation"),
                },
            },
            "device_name": "YubiKey",
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["message"] == "Security key registered."
    assert body["credential"]["device_name"] == "YubiKey"
    with app.app_context():
        saved = WebAuthnCredential.query.one()
        assert saved.credential_id == _b64url(b"new-key")
        assert saved.public_key == b"verified-public-key"
        assert saved.sign_count == 7


def test_webauthn_register_complete_logs_failure_without_saving(client, app, monkeypatch):
    headers = _authenticated_headers(client)
    begin = client.post("/api/auth/webauthn/register/begin", headers=headers, json={})

    def reject_registration(**kwargs):
        raise ValueError("invalid attestation")

    monkeypatch.setattr("app.routes.auth.verify_registration_response", reject_registration)
    response = client.post(
        "/api/auth/webauthn/register/complete",
        headers=headers,
        json={
            "challenge_token": begin.get_json()["challenge_token"],
            "credential": {
                "id": _b64url(b"raw-key"),
                "rawId": _b64url(b"raw-key"),
                "response": {
                    "clientDataJSON": _b64url(b"client-data"),
                    "attestationObject": _b64url(b"attestation"),
                },
            },
        },
    )

    assert response.status_code == 400
    with app.app_context():
        assert WebAuthnCredential.query.count() == 0
        assert AuditLog.query.filter_by(event_type="webauthn_registration_failed").count() == 1


def _create_login_credential(client, app, credential_id=b"login-key", sign_count=1):
    register(client)
    with app.app_context():
        user = User.query.filter_by(username="alice").first()
        db.session.add(WebAuthnCredential(
            user_id=user.id,
            credential_id=_b64url(credential_id),
            public_key=b"login-public-key",
            sign_count=sign_count,
        ))
        db.session.commit()


def _assertion_credential(credential_id=b"login-key"):
    encoded_id = _b64url(credential_id)
    return {
        "id": encoded_id,
        "rawId": encoded_id,
        "response": {
            "clientDataJSON": _b64url(b"client-data"),
            "authenticatorData": _b64url(b"authenticator-data"),
            "signature": _b64url(b"signature"),
            "userHandle": None,
        },
    }


def test_webauthn_login_begin_returns_options_for_known_and_unknown_users(client, app):
    _create_login_credential(client, app)

    known = client.post("/api/auth/webauthn/login/begin", json={"username": "alice"})
    unknown = client.post("/api/auth/webauthn/login/begin", json={"username": "nobody"})

    assert known.status_code == 200
    assert unknown.status_code == 200
    known_body = known.get_json()
    unknown_body = unknown.get_json()
    assert set(known_body) == {"options", "challenge_token"}
    assert set(unknown_body) == {"options", "challenge_token"}
    assert known_body["options"]["allowCredentials"][0]["id"] == _b64url(b"login-key")
    with app.app_context():
        known_payload = decode_token(known_body["challenge_token"])
        unknown_payload = decode_token(unknown_body["challenge_token"])
    assert known_payload["purpose"] == "webauthn_login"
    assert known_payload["challenge"] == known_body["options"]["challenge"]
    assert unknown_payload["sub"] == 0


def test_webauthn_login_begin_rejects_user_without_registered_keys(client):
    register(client)

    response = client.post("/api/auth/webauthn/login/begin", json={"username": "alice"})

    assert response.status_code == 400
    assert response.get_json()["error"] == "No security key registered for this account."


def test_webauthn_login_complete_verifies_and_creates_session(client, app, monkeypatch):
    _create_login_credential(client, app)
    begin = client.post("/api/auth/webauthn/login/begin", json={"username": "alice"})
    challenge_token = begin.get_json()["challenge_token"]

    def verify_authentication_response(**kwargs):
        assert kwargs["expected_rp_id"] == app.config["WEBAUTHN_RP_ID"]
        assert kwargs["expected_origin"] == app.config["WEBAUTHN_ORIGIN"]
        assert kwargs["credential_public_key"] == b"login-public-key"
        assert kwargs["credential_current_sign_count"] == 1
        assert kwargs["credential"].raw_id == b"login-key"
        assert kwargs["credential"].response.signature == b"signature"
        return SimpleNamespace(new_sign_count=2)

    monkeypatch.setattr(
        "app.routes.auth.verify_authentication_response", verify_authentication_response
    )
    response = client.post(
        "/api/auth/webauthn/login/complete",
        json={"challenge_token": challenge_token, "credential": _assertion_credential()},
    )

    assert response.status_code == 200
    body = response.get_json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["user"]["username"] == "alice"
    with app.app_context():
        assert WebAuthnCredential.query.one().sign_count == 2
        assert Session.query.count() == 1
        attempt = LoginAttempt.query.filter_by(stage="webauthn", success=True).one()
        assert attempt.username_tried == "alice"


def test_webauthn_login_complete_rejects_replayed_counter(client, app, monkeypatch):
    _create_login_credential(client, app, sign_count=2)
    begin = client.post("/api/auth/webauthn/login/begin", json={"username": "alice"})
    monkeypatch.setattr(
        "app.routes.auth.verify_authentication_response",
        lambda **kwargs: SimpleNamespace(new_sign_count=2),
    )

    response = client.post(
        "/api/auth/webauthn/login/complete",
        json={
            "challenge_token": begin.get_json()["challenge_token"],
            "credential": _assertion_credential(),
        },
    )

    assert response.status_code == 401
    assert response.get_json()["error"] == "WebAuthn verification failed."
    with app.app_context():
        assert WebAuthnCredential.query.one().sign_count == 2
        assert Session.query.count() == 0
        attempt = LoginAttempt.query.filter_by(stage="webauthn", success=False).one()
        assert attempt.reason == "replayed_assertion"