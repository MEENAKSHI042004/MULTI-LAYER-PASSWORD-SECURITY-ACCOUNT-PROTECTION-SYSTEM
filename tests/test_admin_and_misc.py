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


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_dashboard_index_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"MLPSAPS" in resp.data
