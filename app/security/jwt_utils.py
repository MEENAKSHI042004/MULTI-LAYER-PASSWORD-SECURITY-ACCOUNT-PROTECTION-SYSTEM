"""
JWT Session Management Module.

Issues short-lived access tokens and longer-lived refresh tokens signed with
HS256. Access tokens carry the user id and a token "purpose" claim so a
partially-authenticated (password-only, pre-MFA) state can be represented
distinctly from a fully-authenticated session -- this prevents a client from
skipping the MFA step by reusing a pre-MFA token against protected routes.

Every token also carries a "jti" (JWT ID) -- a random unique identifier for
that specific token issuance. This is what lets logout/revocation work with
an otherwise-stateless JWT: revoking a token means recording its jti as
revoked, and every verification checks the jti against that record.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt
from flask import current_app


def _encode(payload: dict, expires_delta: timedelta) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    to_encode = payload.copy()
    to_encode.update({"iat": now, "exp": now + expires_delta, "jti": jti})
    token = jwt.encode(
        to_encode,
        current_app.config["JWT_SECRET_KEY"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )
    return token, jti


def create_pre_mfa_token(user_id: int) -> str:
    """Issued after correct password but before MFA is verified. Cannot be used
    to access protected resources -- only the /verify-mfa endpoint accepts it."""
    minutes = 5  # short-lived: must complete MFA quickly
    token, _jti = _encode({"sub": user_id, "purpose": "pre_mfa"}, timedelta(minutes=minutes))
    return token


def create_access_token(user_id: int) -> tuple[str, str]:
    """Returns (token, jti). Callers that need to record a session (login,
    verify_mfa) use the jti; callers that just need the token can ignore it."""
    minutes = current_app.config["JWT_ACCESS_TOKEN_MINUTES"]
    return _encode({"sub": user_id, "purpose": "access"}, timedelta(minutes=minutes))


def create_refresh_token(user_id: int) -> tuple[str, str]:
    days = current_app.config["JWT_REFRESH_TOKEN_DAYS"]
    return _encode({"sub": user_id, "purpose": "refresh"}, timedelta(days=days))


def decode_token(token: str) -> dict:
    """Decode and validate a token's signature/expiry. Raises jwt exceptions on failure.
    The returned payload includes "jti" -- callers that need revocation/session
    checks (e.g. the token_required decorator) read it from here.

    Tries JWT_SECRET_KEY first, then JWT_SECRET_KEY_PREVIOUS if set. This lets a
    secret be rotated without instantly invalidating every outstanding token:
    tokens signed with the old secret keep verifying (until they naturally
    expire) while all new tokens are signed with the new one."""
    secrets_to_try = [current_app.config["JWT_SECRET_KEY"]]
    if current_app.config.get("JWT_SECRET_KEY_PREVIOUS"):
        secrets_to_try.append(current_app.config["JWT_SECRET_KEY_PREVIOUS"])

    last_error = None
    for secret in secrets_to_try:
        try:
            return jwt.decode(
                token,
                secret,
                algorithms=[current_app.config["JWT_ALGORITHM"]],
            )
        except jwt.InvalidSignatureError as e:
            last_error = e
            continue
    raise last_error