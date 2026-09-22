"""
Configuration for the Multi-Layer Password Security & Account Protection System.

All security-sensitive values are read from environment variables with safe
development defaults. In production, JWT_SECRET_KEY and FLASK_SECRET_KEY
MUST be overridden with long random values (see SECURITY.md).
"""

import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # --- Core Flask ---
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'app.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- JWT session management ---
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-only-change-me-too")
    JWT_SECRET_KEY_PREVIOUS = os.environ.get("JWT_SECRET_KEY_PREVIOUS", None)
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_MINUTES = int(os.environ.get("JWT_ACCESS_TOKEN_MINUTES", 15))
    JWT_REFRESH_TOKEN_DAYS = int(os.environ.get("JWT_REFRESH_TOKEN_DAYS", 7))

    # --- Password hashing (bcrypt) ---
    # 12 rounds is the widely recommended minimum work factor for bcrypt as of 2026.
    BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", 12))

    # --- Password policy ---
    PASSWORD_MIN_LENGTH = 10
    PASSWORD_MAX_LENGTH = 128
    PASSWORD_REQUIRE_UPPER = True
    PASSWORD_REQUIRE_LOWER = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_EXPIRY_DAYS = 90
    PASSWORD_HISTORY_SIZE = 5  # block re-use of last N passwords

    # --- Brute-force / adaptive lockout ---
    MAX_FAILED_ATTEMPTS = 5          # failures before first lockout
    BASE_LOCKOUT_SECONDS = 30        # first lockout duration
    LOCKOUT_BACKOFF_FACTOR = 2       # exponential multiplier per subsequent lockout
    MAX_LOCKOUT_SECONDS = 3600       # cap lockout at 1 hour

    # --- TOTP / MFA ---
    TOTP_ISSUER = "MLPSAPS-CIT"
    TOTP_VALID_WINDOW = 1            # allow +/- 1 time-step (30s) clock drift
    RECOVERY_CODE_COUNT = 8

    # --- Rate limiting (Flask-Limiter) ---
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_LOGIN = "10 per minute"
    RATELIMIT_LOGIN_PER_USERNAME = "5 per minute"
    RATELIMIT_REGISTER = "3 per minute"
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

    # --- CORS ---
    # Only the storefront's own origin may call the API cross-origin. Never use
    # "*" here -- an auth API (login/register/me/tokens) with open CORS would
    # let any website on the internet read a logged-in user's session data via
    # a background fetch() from the victim's browser.
    CORS_ALLOWED_ORIGINS = os.environ.get(
        "CORS_ALLOWED_ORIGINS", "http://127.0.0.1:5001,http://localhost:5001"
    ).split(",")


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    BCRYPT_ROUNDS = 4  # fast hashing for test speed only, never in production
    RATELIMIT_ENABLED = False
