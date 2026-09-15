"""
Password Hashing Module.

Design decision (see SECURITY.md for full rationale):
  - bcrypt is used because it has a built-in per-hash random salt, an
    adjustable work factor, and ~15 years of cryptanalytic scrutiny.
  - We never store or transmit plaintext passwords; only the bcrypt hash
    (which itself embeds the salt and cost factor) is persisted.
"""

import bcrypt
from flask import current_app


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password with a fresh random salt."""
    rounds = current_app.config.get("BCRYPT_ROUNDS", 12)
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Constant-time comparison of a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        # Malformed hash -- fail closed.
        return False
