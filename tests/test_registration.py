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
        assert user.password_hash.startswith("$2b$")
