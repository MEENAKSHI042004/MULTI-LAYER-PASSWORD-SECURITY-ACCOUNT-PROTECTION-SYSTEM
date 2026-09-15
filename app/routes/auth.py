"""
Authentication REST endpoints.

  POST /api/auth/register        - create account (password policy enforced)
  POST /api/auth/login           - stage 1: password check (brute-force guarded)
  POST /api/auth/verify-mfa      - stage 2: TOTP or recovery code check
  POST /api/auth/mfa/setup       - begin MFA enrolment (returns QR provisioning URI)
  POST /api/auth/mfa/confirm     - confirm enrolment with a valid TOTP code
  POST /api/auth/refresh         - exchange refresh token for new access token
  POST /api/auth/logout          - client-side token discard endpoint (stateless JWT)
  POST /api/auth/change-password - authenticated password change
  GET  /api/auth/me              - current session info
"""

from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, g, current_app

from app.extensions import db, limiter
from app.models import User, PasswordHistory
from app.security.hashing import hash_password, verify_password
from app.security.password_validator import validate_password_strength, is_password_expired
from app.security.brute_force import (
    get_active_lockout,
    seconds_until_unlock,
    record_attempt,
    register_failure_and_maybe_lock,
)
from app.security.totp_utils import (
    generate_totp_secret,
    get_provisioning_uri,
    verify_totp_code,
    generate_recovery_codes,
    consume_recovery_code,
)
from app.security.jwt_utils import create_pre_mfa_token, create_access_token, create_refresh_token
from app.security.audit_logger import log_event
from app.security.decorators import token_required

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"


@auth_bp.route("/register", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_REGISTER"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "username, email and password are required."}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "Username or email already registered."}), 409

    errors = validate_password_strength(password)
    if errors:
        return jsonify({"error": "Password does not meet policy.", "details": errors}), 400

    user = User(username=username, email=email, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()

    db.session.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash))
    db.session.commit()

    log_event("register", ip_address=_client_ip(), user_id=user.id)
    return jsonify({"message": "Registration successful.", "user": user.to_public_dict()}), 201


@auth_bp.route("/login", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_LOGIN"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    ip = _client_ip()

    user = User.query.filter_by(username=username).first()

    # Active lockout check happens before password verification so we don't
    # leak timing information about whether the password itself is correct.
    if user:
        lockout = get_active_lockout(user)
        if lockout:
            record_attempt(user, username, ip, success=False, stage="password", reason="locked")
            log_event("login_blocked_lockout", ip_address=ip, user_id=user.id)
            return jsonify({
                "error": "Account temporarily locked due to repeated failed attempts.",
                "retry_after_seconds": seconds_until_unlock(user),
            }), 423

    if not user or not verify_password(password, user.password_hash):
        if user:
            record_attempt(user, username, ip, success=False, stage="password", reason="bad_password")
            new_lockout = register_failure_and_maybe_lock(user)
            if new_lockout:
                log_event(
                    "account_locked", ip_address=ip, user_id=user.id,
                    details=f"lockout #{new_lockout.lockout_number}, {new_lockout.duration_seconds}s",
                )
        else:
            # Unknown username: still logged (username enumeration signal) but
            # cannot be tied to a lockout since there's no account to lock.
            record_attempt(None, username, ip, success=False, stage="password", reason="unknown_user")
        log_event("login_failed", ip_address=ip, details=f"username={username}")
        return jsonify({"error": "Invalid username or password."}), 401

    record_attempt(user, username, ip, success=True, stage="password")
    log_event("login_password_ok", ip_address=ip, user_id=user.id)

    if is_password_expired(user.password_changed_at):
        return jsonify({
            "error": "Password expired; please change your password.",
            "password_expired": True,
        }), 403

    if user.mfa_enabled:
        pre_token = create_pre_mfa_token(user.id)
        return jsonify({"mfa_required": True, "pre_mfa_token": pre_token}), 200

    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)
    log_event("login_success", ip_address=ip, user_id=user.id)
    return jsonify({"access_token": access, "refresh_token": refresh, "user": user.to_public_dict()}), 200


@auth_bp.route("/verify-mfa", methods=["POST"])
@token_required(purpose="pre_mfa")
def verify_mfa():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    use_recovery = bool(data.get("use_recovery_code"))
    user = g.current_user
    ip = _client_ip()

    ok = consume_recovery_code(user, code) if use_recovery else verify_totp_code(user.totp_secret, code)

    if not ok:
        record_attempt(user, user.username, ip, success=False, stage="mfa", reason="bad_code")
        new_lockout = register_failure_and_maybe_lock(user)
        if new_lockout:
            log_event("account_locked", ip_address=ip, user_id=user.id, details="locked at MFA stage")
        log_event("mfa_failed", ip_address=ip, user_id=user.id)
        return jsonify({"error": "Invalid MFA code."}), 401

    record_attempt(user, user.username, ip, success=True, stage="mfa")
    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)
    log_event("login_success", ip_address=ip, user_id=user.id, details="via MFA")
    return jsonify({"access_token": access, "refresh_token": refresh, "user": user.to_public_dict()}), 200


@auth_bp.route("/mfa/setup", methods=["POST"])
@token_required(purpose="access")
def mfa_setup():
    user = g.current_user
    secret = generate_totp_secret()
    user.totp_secret = secret  # not yet enabled until /mfa/confirm
    db.session.commit()
    uri = get_provisioning_uri(secret, user.username)
    return jsonify({"secret": secret, "provisioning_uri": uri}), 200


@auth_bp.route("/mfa/confirm", methods=["POST"])
@token_required(purpose="access")
def mfa_confirm():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    user = g.current_user

    if not user.totp_secret or not verify_totp_code(user.totp_secret, code):
        return jsonify({"error": "Invalid code; MFA not enabled."}), 400

    user.mfa_enabled = True
    db.session.commit()
    codes = generate_recovery_codes(user)
    log_event("mfa_enabled", ip_address=_client_ip(), user_id=user.id)
    return jsonify({
        "message": "MFA enabled.",
        "recovery_codes": codes,
        "note": "Store these recovery codes safely -- they will not be shown again.",
    }), 200


@auth_bp.route("/refresh", methods=["POST"])
@token_required(purpose="refresh")
def refresh():
    user = g.current_user
    access = create_access_token(user.id)
    return jsonify({"access_token": access}), 200


@auth_bp.route("/logout", methods=["POST"])
@token_required(purpose="access")
def logout():
    # JWTs are stateless; logout is enforced client-side by discarding tokens.
    # A production system could additionally maintain a short-lived denylist
    # of revoked token ids (jti) for the remaining access-token lifetime.
    log_event("logout", ip_address=_client_ip(), user_id=g.current_user.id)
    return jsonify({"message": "Logged out."}), 200


@auth_bp.route("/change-password", methods=["POST"])
@token_required(purpose="access")
def change_password():
    data = request.get_json(silent=True) or {}
    current = data.get("current_password") or ""
    new_password = data.get("new_password") or ""
    user = g.current_user

    if not verify_password(current, user.password_hash):
        return jsonify({"error": "Current password is incorrect."}), 401

    errors = validate_password_strength(new_password)
    if errors:
        return jsonify({"error": "Password does not meet policy.", "details": errors}), 400

    history_limit = current_app.config.get("PASSWORD_HISTORY_SIZE", 5)
    recent = (
        PasswordHistory.query.filter_by(user_id=user.id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(history_limit)
        .all()
    )
    for old in recent:
        if verify_password(new_password, old.password_hash):
            return jsonify({"error": f"Cannot reuse any of your last {history_limit} passwords."}), 400

    user.password_hash = hash_password(new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    db.session.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash))
    db.session.commit()

    log_event("password_changed", ip_address=_client_ip(), user_id=user.id)
    return jsonify({"message": "Password changed successfully."}), 200


@auth_bp.route("/me", methods=["GET"])
@token_required(purpose="access")
def me():
    return jsonify({"user": g.current_user.to_public_dict()}), 200
