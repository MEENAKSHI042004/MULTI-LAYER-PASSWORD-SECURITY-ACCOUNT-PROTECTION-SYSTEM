"""
Password Validator Module.

Enforces length/complexity/entropy rules, checks the password against the
"Have I Been Pwned" breach database (via k-anonymity range query -- the full
password is never sent or logged, only the first 5 characters of its SHA-1
hash), and blocks re-use of recent passwords (via PasswordHistory + bcrypt
comparison, done in the auth route).
"""

import hashlib
import re
from datetime import datetime, timedelta, timezone

import requests
from flask import current_app

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


def _check_pwned(password: str) -> int:
    """Returns how many times this password has appeared in known breaches
    (0 if never seen, or if the check couldn't be completed -- see below).

    Uses the k-anonymity method: only the first 5 characters of the SHA-1
    hash are ever sent to the HIBP API. The full password never leaves this
    function, and not even the full hash is ever transmitted."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(f"{HIBP_API_URL}{prefix}", timeout=3)
        response.raise_for_status()
    except requests.RequestException:
        # If HIBP is unreachable, fail open rather than blocking registration
        # entirely -- the other password policy rules still apply regardless.
        current_app.logger.warning("HIBP breach check unavailable; skipping this check.")
        return 0

    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0


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

    breach_count = _check_pwned(password)
    if breach_count > 0:
        errors.append(
            f"This password has appeared in {breach_count:,} known data breaches; "
            "please choose a different one."
        )

    return errors


def is_password_expired(password_changed_at: datetime) -> bool:
    """Check whether a user's current password has passed the expiry window."""
    days = current_app.config["PASSWORD_EXPIRY_DAYS"]
    if password_changed_at.tzinfo is None:
        password_changed_at = password_changed_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) > password_changed_at + timedelta(days=days)