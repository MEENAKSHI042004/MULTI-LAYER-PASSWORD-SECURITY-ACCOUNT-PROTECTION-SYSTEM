import pyotp

from tests.conftest import register, login


def _get_access_token(client):
    register(client)
    resp = login(client)
    return resp.get_json()["access_token"]


def test_mfa_setup_and_confirm_flow(client):
    token = _get_access_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    setup_resp = client.post("/api/auth/mfa/setup", headers=headers)
    assert setup_resp.status_code == 200
    secret = setup_resp.get_json()["secret"]

    code = pyotp.TOTP(secret).now()
    confirm_resp = client.post("/api/auth/mfa/confirm", headers=headers, json={"code": code})
    assert confirm_resp.status_code == 200
    body = confirm_resp.get_json()
    assert len(body["recovery_codes"]) == 8


def test_login_requires_mfa_after_enrolment(client):
    token = _get_access_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    setup_resp = client.post("/api/auth/mfa/setup", headers=headers)
    secret = setup_resp.get_json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/auth/mfa/confirm", headers=headers, json={"code": code})

    # Now logging in again should require MFA rather than returning tokens directly.
    login_resp = login(client)
    assert login_resp.status_code == 200
    body = login_resp.get_json()
    assert body["mfa_required"] is True
    assert "pre_mfa_token" in body

    # Complete MFA with a fresh TOTP code.
    new_code = pyotp.TOTP(secret).now()
    verify_resp = client.post(
        "/api/auth/verify-mfa",
        headers={"Authorization": "Bearer " + body["pre_mfa_token"]},
        json={"code": new_code},
    )
    assert verify_resp.status_code == 200
    assert "access_token" in verify_resp.get_json()


def test_pre_mfa_token_cannot_access_protected_routes(client):
    token = _get_access_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    setup_resp = client.post("/api/auth/mfa/setup", headers=headers)
    secret = setup_resp.get_json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/auth/mfa/confirm", headers=headers, json={"code": code})

    login_resp = login(client)
    pre_token = login_resp.get_json()["pre_mfa_token"]

    # A pre-MFA token must not work against a normal 'access' route.
    me_resp = client.get("/api/auth/me", headers={"Authorization": "Bearer " + pre_token})
    assert me_resp.status_code == 401


def test_recovery_code_can_be_used_once(client):
    token = _get_access_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    setup_resp = client.post("/api/auth/mfa/setup", headers=headers)
    secret = setup_resp.get_json()["secret"]
    code = pyotp.TOTP(secret).now()
    confirm_resp = client.post("/api/auth/mfa/confirm", headers=headers, json={"code": code})
    recovery_code = confirm_resp.get_json()["recovery_codes"][0]

    login_resp = login(client)
    pre_token = login_resp.get_json()["pre_mfa_token"]

    verify_resp = client.post(
        "/api/auth/verify-mfa",
        headers={"Authorization": "Bearer " + pre_token},
        json={"code": recovery_code, "use_recovery_code": True},
    )
    assert verify_resp.status_code == 200

    # Re-using the same recovery code should now fail.
    login_resp2 = login(client)
    pre_token2 = login_resp2.get_json()["pre_mfa_token"]
    verify_resp2 = client.post(
        "/api/auth/verify-mfa",
        headers={"Authorization": "Bearer " + pre_token2},
        json={"code": recovery_code, "use_recovery_code": True},
    )
    assert verify_resp2.status_code == 401
