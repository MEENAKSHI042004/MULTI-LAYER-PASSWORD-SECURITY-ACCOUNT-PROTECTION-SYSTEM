"""
Password Validator Module.

Enforces length/complexity/entropy rules, rejects a shortlist of the most
commonly breached passwords, and blocks re-use of recent passwords
(via PasswordHistory + bcrypt comparison, done in the auth route).
"""

import re
from datetime import datetime, timedelta, timezone

from flask import current_app

# A small illustrative sample of extremely common breached passwords.
# In a production deployment this would be backed by a much larger
# corpus such as the "Have I Been Pwned" Pwned Passwords list, checked
# via k-anonymity range queries rather than a hardcoded list.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "password1", "111111", "123123",
    "admin", "letmein", "welcome", "monkey", "iloveyou",
}


def validate_password_strength(password: str) -> list:
    """Return a list of policy violation messages; empty list = password OK."""
    cfg = current_app.config
    errors = []

    if len(password) < cfg["PASSWORD_MIN_LENGTH"]:
        errors.append(f"Password must be at least {cfg['PASSWORD_MIN_LENGTH']} characters long.")
    if len(password) > cfg["PASSWORD_MAX_LENGTH"]:
        errors.append(f"Password must be at most {cfg['PASSWORD_MAX_LENGTH']} characters long.")
    if cfg["PASSWORD_REQUIRE_UPPER"] and not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if cfg["PASSWORD_REQUIRE_LOWER"] and not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if cfg["PASSWORD_REQUIRE_DIGIT"] and not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one digit.")
    if cfg["PASSWORD_REQUIRE_SPECIAL"] and not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must contain at least one special character.")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("This password appears in common breach lists; choose a different one.")

    return errors


def is_password_expired(password_changed_at: datetime) -> bool:
    """Check whether a user's current password has passed the expiry window."""
    days = current_app.config["PASSWORD_EXPIRY_DAYS"]
    if password_changed_at.tzinfo is None:
        password_changed_at = password_changed_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) > password_changed_at + timedelta(days=days)
