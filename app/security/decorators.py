"""Route decorators enforcing JWT auth (and its 'purpose' claim)."""

from functools import wraps

import jwt
from flask import request, jsonify, g

from app.security.jwt_utils import decode_token
from app.models import User


def _extract_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header.split(" ", 1)[1].strip()


def token_required(purpose="access"):
    """Require a valid JWT of the given purpose ('access', 'pre_mfa', 'refresh')."""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = _extract_bearer_token()
            if not token:
                return jsonify({"error": "Missing bearer token."}), 401
            try:
                payload = decode_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token has expired."}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid token."}), 401

            if payload.get("purpose") != purpose:
                return jsonify({"error": "Token not valid for this operation."}), 401

            user = User.query.get(payload.get("sub"))
            if not user or not user.is_active:
                return jsonify({"error": "User not found or inactive."}), 401

            g.current_user = user
            return f(*args, **kwargs)

        return wrapper

    return decorator


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = getattr(g, "current_user", None)
        if not user or not user.is_admin:
            return jsonify({"error": "Admin privileges required."}), 403
        return f(*args, **kwargs)

    return wrapper
