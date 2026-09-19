from tests.conftest import register


def test_register_success(client):
    resp = register(client)
    assert resp.status_code == 201
    assert resp.get_json()["user"]["username"] == "alice"


def test_register_rejects_weak_password(client):
    resp = client.post("/api/auth/register", json={
        "username": "bob", "email": "bob@example.com", "password": "password"
    })
    assert resp.status_code == 400
    assert "details" in resp.get_json()


def test_register_rejects_duplicate_username(client):
    register(client)
    resp = register(client, email="other@example.com")
    assert resp.status_code == 409


def test_password_never_stored_in_plaintext(client, app):
    register(client)
    from app.models import User
    with app.app_context():
        user = User.query.filter_by(username="alice").first()
        assert user.password_hash != "Str0ng!Passw0rd"
        # Argon2id hashes are self-identifying via this prefix; this also
        # confirms the migration off bcrypt (which used $2b$) for all new
        # registrations.
        assert user.password_hash.startswith("$argon2id$")


def test_registration_rejects_breached_password(client, monkeypatch):
    monkeypatch.setattr("app.security.password_validator.check_pwned", lambda pw: 999999)
    resp = register(client, password="Str0ng!Passw0rd")
    assert resp.status_code == 400
    body = resp.get_json()
    assert any("data breaches" in detail for detail in body["details"])