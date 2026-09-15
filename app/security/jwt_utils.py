"""
JWT Session Management Module.

Issues short-lived access tokens and longer-lived refresh tokens signed with
HS256. Access tokens carry the user id and a token "purpose" claim so a
partially-authenticated (password-only, pre-MFA) state can be represented
distinctly from a fully-authenticated session -- this prevents a client from
skipping the MFA step by reusing a pre-MFA token against protected routes.
"""

from datetime import datetime, timedelta, timezone

import jwt
from flask import current_app


def _encode(payload: dict, expires_delta: timedelta) -> str:
    now = datetime.now(timezone.utc)
    to_encode = payload.copy()
    to_encode.update({"iat": now, "exp": now + expires_delta})
    return jwt.encode(
        to_encode,
        current_app.config["JWT_SECRET_KEY"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )


def create_pre_mfa_token(user_id: int) -> str:
    """Issued after correct password but before MFA is verified. Cannot be used
    to access protected resources -- only the /verify-mfa endpoint accepts it."""
    minutes = 5  # short-lived: must complete MFA quickly
    return _encode({"sub": user_id, "purpose": "pre_mfa"}, timedelta(minutes=minutes))


def create_access_token(user_id: int) -> str:
    minutes = current_app.config["JWT_ACCESS_TOKEN_MINUTES"]
    return _encode({"sub": user_id, "purpose": "access"}, timedelta(minutes=minutes))


def create_refresh_token(user_id: int) -> str:
    days = current_app.config["JWT_REFRESH_TOKEN_DAYS"]
    return _encode({"sub": user_id, "purpose": "refresh"}, timedelta(days=days))


def decode_token(token: str) -> dict:
    """Decode and validate a token's signature/expiry. Raises jwt exceptions on failure."""
    return jwt.decode(
        token,
        current_app.config["JWT_SECRET_KEY"],
        algorithms=[current_app.config["JWT_ALGORITHM"]],
    )
