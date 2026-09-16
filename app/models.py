"""
Database models.

Tables map directly onto the modules described in the project abstract:
  - User              -> credential storage (Password Hashing Module)
  - PasswordHistory    -> Password Validator (reuse prevention)
  - LoginAttempt       -> Brute Force Prevention module (raw attempt log)
  - Lockout            -> Brute Force Prevention module (active/expired locks)
  - AuditLog           -> Security Audit Logging module
  - RecoveryCode        -> TOTP MFA module (one-time backup codes)
  - RevokedToken        -> revoked/cancelled JWTs (logout / session revocation)
  - Session             -> active login sessions per user (view/end sessions)
"""

from datetime import datetime, timezone

from app.extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    password_changed_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    # TOTP / MFA
    totp_secret = db.Column(db.String(64), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)

    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    password_history = db.relationship(
        "PasswordHistory", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    login_attempts = db.relationship(
        "LoginAttempt", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    lockouts = db.relationship(
        "Lockout", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    recovery_codes = db.relationship(
        "RecoveryCode", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    sessions = db.relationship(
        "Session", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    def to_public_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "mfa_enabled": self.mfa_enabled,
            "created_at": self.created_at.isoformat(),
        }


class PasswordHistory(db.Model):
    __tablename__ = "password_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username_tried = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(64), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    stage = db.Column(db.String(32), nullable=False)  # 'password' | 'mfa'
    reason = db.Column(db.String(128), nullable=True)  # e.g. 'bad_password', 'locked'
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class Lockout(db.Model):
    __tablename__ = "lockouts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    lockout_number = db.Column(db.Integer, nullable=False)  # 1st, 2nd, 3rd... lockout
    locked_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    unlock_at = db.Column(db.DateTime, nullable=False)
    duration_seconds = db.Column(db.Integer, nullable=False)


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    event_type = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "event_type": self.event_type,
            "ip_address": self.ip_address,
            "details": self.details,
            "created_at": self.created_at.isoformat(),
        }


class RecoveryCode(db.Model):
    __tablename__ = "recovery_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    code_hash = db.Column(db.String(255), nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class RevokedToken(db.Model):
    """A cancelled token. If a token's jti shows up here, it can no longer be used,
    even if it hasn't technically expired yet."""
    __tablename__ = "revoked_tokens"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)  # copy of the token's own expiry,
    # so a cleanup job can safely delete old rows once the token would've expired anyway


class Session(db.Model):
    """One row per login. Lets a user see 'I'm logged in on 2 devices' and end one."""
    __tablename__ = "sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)
    refresh_jti = db.Column(db.String(36), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat(),
            "last_seen_at": self.last_seen_at.isoformat(),
        }