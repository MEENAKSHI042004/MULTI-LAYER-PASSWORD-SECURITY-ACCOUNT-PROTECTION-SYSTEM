"""
Password Hashing Module.

Design decision (see SECURITY.md for full rationale):
  - New passwords are hashed with Argon2id (via argon2-cffi), the winner of
    the 2015 Password Hashing Competition and current OWASP recommendation.
    It is memory-hard, making it significantly more expensive to attack with
    GPUs/ASICs than bcrypt, while still auto-generating a fresh random salt
    per hash and embedding its parameters (memory cost, time cost,
    parallelism) directly in the stored hash string.
  - Existing accounts created before this migration have bcrypt hashes
    already in the database. verify_password() detects which algorithm a
    given hash belongs to (by its prefix) and verifies against the correct
    one, so no user is locked out and no mass password reset is needed.
  - We never store or transmit plaintext passwords; only the resulting hash
    (bcrypt or Argon2id, each of which embeds its own salt/cost parameters)
    is persisted.
"""

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import current_app

ph = PasswordHasher()


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password with Argon2id (fresh random salt, current
    OWASP-recommended parameters). All new and changed passwords use this."""
    return ph.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored hash, transparently
    supporting both legacy bcrypt hashes (identifiable by their $2a$/$2b$
    prefix) and current Argon2id hashes. Returns False, never raises, on
    any mismatch or malformed hash -- fail closed."""
    if password_hash.startswith("$2a$") or password_hash.startswith("$2b$"):
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
        except (ValueError, TypeError):
            return False

    try:
        return ph.verify(password_hash, plain_password)
    except VerifyMismatchError:
        return False
    except Exception:
        # Malformed/unrecognized hash -- fail closed rather than raise.
        return False
