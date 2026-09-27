import base64
from types import SimpleNamespace

from app.extensions import db
from app.models import AuditLog, User, WebAuthnCredential
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