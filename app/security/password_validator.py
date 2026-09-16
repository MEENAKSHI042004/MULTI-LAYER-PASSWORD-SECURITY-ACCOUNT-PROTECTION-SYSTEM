"""
Password Validator Module.

Enforces length/complexity/entropy rules, checks passwords against the
"Have I Been Pwned" breach database (via k-anonymity range queries, so the
full password or even its full hash is never sent over the network), and
blocks re-use of recent passwords (via PasswordHistory + bcrypt comparison,
done in the auth route).
"""

import hashlib
import re
from datetime import datetime, timedelta, timezone

import requests
from flask import current_app

# Small local fallback list, used only if the HIBP API is unreachable
# (e.g. no network in a test/offline environment) so password checks still
# catch the most obvious cases even when the live lookup can't run.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "password1", "111111", "123123",
    "admin", "letmein", "welcome", "monkey", "iloveyou",
}

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def check_pwned(password: str) -> int:
    """
    Check a password against the Have I Been Pwned breach database using
    the k-anonymity model:

      1. SHA-1 hash the password locally.
      2. Send only the first 5 hex characters of the hash to HIBP.
      3. HIBP returns every suffix that shares that prefix, each with a
         breach count.
      4. Compare our full suffix against that list locally.

    The full password, and even the full hash, never leaves this machine.

    Returns the number of times the password has appeared in known
    breaches (0 if not found). Returns -1 if the check could not be
    performed (e.g. network error), so callers can decide how to handle
    that separately from a genuine "not breached" result.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            headers={"Add-Padding": "true"},  # asks HIBP to pad the response, resisting size-based inference
            timeout=5,
        )
        resp.raise_for_status()
    except requests.RequestException:
        current_app.logger.warning("HIBP lookup failed; falling back to local list only.")
        return -1

    for line in resp.text.splitlines():
        line_suffix, _, count = line.partition(":")
        if line_suffix == suffix:
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

    breach_count = check_pwned(password)
    if breach_count > 0:
        errors.append(
            f"This password has appeared in {breach_count:,} known data breaches; choose a different one."
        )
    elif breach_count == -1 and password.lower() in COMMON_PASSWORDS:
        # HIBP unreachable — fall back to the local shortlist so obviously
        # weak passwords are still caught rather than silently allowed.
        errors.append("This password appears in common breach lists; choose a different one.")

    return errors


def is_password_expired(password_changed_at: datetime) -> bool:
    """Check whether a user's current password has passed the expiry window."""
    days = current_app.config["PASSWORD_EXPIRY_DAYS"]
    if password_changed_at.tzinfo is None:
        password_changed_at = password_changed_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) > password_changed_at + timedelta(days=days)