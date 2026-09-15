"""
TOTP (Time-based One-Time Password) MFA Module.

Uses pyotp (RFC 6238) for code generation/verification. Secrets are stored
per-user; provisioning is exposed as an otpauth:// URI which the frontend
renders as a QR code for apps like Google Authenticator / Authy.

Recovery codes are generated once at enrolment, shown to the user exactly
once, and stored only as bcrypt hashes (same treatment as passwords) so a
database leak does not expose usable backup codes.
"""

import secrets
import string

import pyotp
from flask import current_app

from app.extensions import db
from app.models import RecoveryCode
from app.security.hashing import hash_password, verify_password


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, username: str) -> str:
    issuer = current_app.config["TOTP_ISSUER"]
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp_code(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    window = current_app.config.get("TOTP_VALID_WINDOW", 1)
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=window)


def _generate_raw_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(2))


def generate_recovery_codes(user) -> list:
    """Create fresh recovery codes for a user, replacing any existing ones.

    Returns the list of PLAINTEXT codes so they can be shown to the user once.
    Only bcrypt hashes are persisted.
    """
    RecoveryCode.query.filter_by(user_id=user.id).delete()

    count = current_app.config.get("RECOVERY_CODE_COUNT", 8)
    plaintext_codes = [_generate_raw_code() for _ in range(count)]
    for code in plaintext_codes:
        db.session.add(RecoveryCode(user_id=user.id, code_hash=hash_password(code)))
    db.session.commit()
    return plaintext_codes


def consume_recovery_code(user, submitted_code: str) -> bool:
    """Check submitted code against unused recovery codes; mark used on match."""
    candidates = RecoveryCode.query.filter_by(user_id=user.id, used=False).all()
    for candidate in candidates:
        if verify_password(submitted_code, candidate.code_hash):
            candidate.used = True
            db.session.commit()
            return True
    return False
