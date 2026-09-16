from tests.conftest import register, login


def test_logout_revokes_refresh_token(client, app):
    register(client)
    resp = login(client)
    body = resp.get_json()
    access_token = body["access_token"]
    refresh_token = body["refresh_token"]

    # Logout using the access token.
    logout_resp = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_resp.status_code == 200

    # The refresh token should now be dead too -- not just the access token.
    refresh_resp = client.post(
        "/api/auth/refresh",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )
    assert refresh_resp.status_code == 401


def test_revoking_a_session_also_revokes_its_refresh_token(client, app):
    register(client)
    resp = login(client)
    body = resp.get_json()
    access_token = body["access_token"]
    refresh_token = body["refresh_token"]

    # Find this session's id via /sessions.
    sessions_resp = client.get(
        "/api/auth/sessions",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    session_id = sessions_resp.get_json()["sessions"][0]["id"]

    revoke_resp = client.post(
        f"/api/auth/sessions/{session_id}/revoke",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert revoke_resp.status_code == 200

    # That session's refresh token should now be dead.
    refresh_resp = client.post(
        "/api/auth/refresh",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )
    assert refresh_resp.status_code == 401