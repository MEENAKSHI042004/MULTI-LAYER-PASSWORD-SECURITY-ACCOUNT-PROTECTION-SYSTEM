from tests.conftest import register, login


def test_login_success_returns_tokens(client):
    register(client)
    resp = login(client)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "access_token" in body
    assert "refresh_token" in body


def test_login_wrong_password_fails(client):
    register(client)
    resp = login(client, password="wrong-password")
    assert resp.status_code == 401


def test_account_locks_after_max_failed_attempts(client, app):
    register(client)
    with app.app_context():
        max_attempts = app.config["MAX_FAILED_ATTEMPTS"]

    for _ in range(max_attempts):
        resp = login(client, password="wrong-password")
        assert resp.status_code == 401

    # Next attempt (even with correct password) should be blocked by lockout.
    resp = login(client)
    assert resp.status_code == 423
    assert "retry_after_seconds" in resp.get_json()


def test_lockout_duration_increases_exponentially(client, app):
    """Trigger two lockouts and confirm the second is longer (exponential backoff)."""
    register(client)
    with app.app_context():
        max_attempts = app.config["MAX_FAILED_ATTEMPTS"]
        base = app.config["BASE_LOCKOUT_SECONDS"]
        factor = app.config["LOCKOUT_BACKOFF_FACTOR"]

    from app.models import Lockout, User
    from app.security.brute_force import _now

    for _ in range(max_attempts):
        login(client, password="wrong-password")

    with app.app_context():
        user = User.query.filter_by(username="alice").first()
        first_lockout = Lockout.query.filter_by(user_id=user.id).order_by(Lockout.id.desc()).first()
        assert first_lockout.duration_seconds == base
        # Force-expire the lockout so we can trigger a second one.
        first_lockout.unlock_at = _now()
        from app.extensions import db
        db.session.commit()

    for _ in range(max_attempts):
        login(client, password="wrong-password")

    with app.app_context():
        user = User.query.filter_by(username="alice").first()
        second_lockout = Lockout.query.filter_by(user_id=user.id).order_by(Lockout.id.desc()).first()
        assert second_lockout.lockout_number == 2
        assert second_lockout.duration_seconds == base * factor


def test_successful_login_resets_failure_counter(client, app):
    register(client)
    with app.app_context():
        max_attempts = app.config["MAX_FAILED_ATTEMPTS"]

    # One failure below threshold, then a success -- should NOT lock.
    for _ in range(max_attempts - 1):
        login(client, password="wrong-password")
    resp = login(client)
    assert resp.status_code == 200

    # Failing again afterwards should require a fresh run of max_attempts.
    for _ in range(max_attempts - 1):
        resp = login(client, password="wrong-password")
        assert resp.status_code == 401
    resp = login(client)  # correct password, should succeed (not locked)
    assert resp.status_code == 200
