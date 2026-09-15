from tests.conftest import register, login


def _admin_headers(app, client):
    with app.app_context():
        username = "admin"
        password = "ChangeMe!2026"
    resp = login(client, username=username, password=password)
    token = resp.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_seeded_admin_can_login_and_view_dashboard(client, app):
    headers = _admin_headers(app, client)
    resp = client.get("/api/admin/stats", headers=headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "total_users" in body


def test_non_admin_cannot_access_dashboard(client):
    register(client)
    resp = login(client)
    token = resp.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/admin/stats", headers=headers)
    assert resp.status_code == 403


def test_audit_log_records_registration_and_login(client, app):
    register(client)
    login(client)
    headers = _admin_headers(app, client)
    resp = client.get("/api/admin/audit-log", headers=headers)
    events = [e["event_type"] for e in resp.get_json()["entries"]]
    assert "register" in events
    assert "login_success" in events


def test_password_reuse_is_blocked(client):
    register(client)
    resp = login(client)
    token = resp.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Change to a new password.
    r1 = client.post("/api/auth/change-password", headers=headers,
                      json={"current_password": "Str0ng!Passw0rd", "new_password": "An0therStr0ng!Pw"})
    assert r1.status_code == 200

    # Try to change back to the original (should be blocked as reuse).
    r2 = client.post("/api/auth/change-password", headers=headers,
                      json={"current_password": "An0therStr0ng!Pw", "new_password": "Str0ng!Passw0rd"})
    assert r2.status_code == 400


def test_account_details_update_requires_auth_and_logs_change(client, app):
    register(client)
    response = client.post("/api/auth/update-account", json={
        "username": "updated-alice", "email": "updated@example.com",
    })
    assert response.status_code == 401

    token = login(client).get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/auth/update-account", headers=headers, json={
        "username": "updated-alice", "email": "UPDATED@example.com",
    })
    assert response.status_code == 200
    assert response.get_json()["user"]["email"] == "updated@example.com"

    with app.app_context():
        from app.models import AuditLog, User
        user = User.query.filter_by(username="updated-alice").first()
        assert user.email == "updated@example.com"
        assert AuditLog.query.filter_by(
            user_id=user.id, event_type="account_updated"
        ).count() == 1


def test_account_details_update_rejects_duplicate_email(client):
    register(client)
    register(client, username="bob", email="bob@example.com")
    token = login(client).get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/api/auth/update-account", headers=headers, json={
        "username": "alice-new", "email": "bob@example.com",
    })
    assert response.status_code == 409


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_dashboard_index_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"MLPSAPS" in resp.data
