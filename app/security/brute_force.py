"""
Brute Force Prevention Module.

Strategy (see SECURITY.md):
  - Every login attempt (success or failure) is written to LoginAttempt.
  - Once a user accrues MAX_FAILED_ATTEMPTS consecutive failures (since their
    last success or last lockout), a Lockout row is created.
  - Lockout duration grows exponentially with each successive lockout for the
    same user: duration = BASE_LOCKOUT_SECONDS * (LOCKOUT_BACKOFF_FACTOR ** (n-1)),
    capped at MAX_LOCKOUT_SECONDS. This makes sustained automated guessing
    increasingly expensive for an attacker while a genuine user only ever
    faces a short delay after one mistaken attempt.
  - Lockouts auto-expire at `unlock_at`; no manual admin action is required,
    though an admin override endpoint is provided.
"""

from datetime import datetime, timedelta, timezone

from flask import current_app

from app.extensions import db
from app.models import LoginAttempt, Lockout, User


def _now():
    return datetime.now(timezone.utc)


def get_active_lockout(user: User):
    """Return the currently active Lockout for a user, or None."""
    lockout = (
        Lockout.query.filter_by(user_id=user.id)
        .order_by(Lockout.locked_at.desc())
        .first()
    )
    if lockout and _aware(lockout.unlock_at) > _now():
        return lockout
    return None


def _aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def seconds_until_unlock(user: User) -> int:
    lockout = get_active_lockout(user)
    if not lockout:
        return 0
    return max(0, int((_aware(lockout.unlock_at) - _now()).total_seconds()))


def record_attempt(user, username_tried, ip_address, success, stage="password", reason=None):
    attempt = LoginAttempt(
        user_id=user.id if user else None,
        username_tried=username_tried,
        ip_address=ip_address,
        success=success,
        stage=stage,
        reason=reason,
    )
    db.session.add(attempt)
    db.session.commit()
    return attempt


def _consecutive_failures_since_last_reset(user: User) -> int:
    """Count failed attempts since the most recent success or lockout event."""
    last_success = (
        LoginAttempt.query.filter_by(user_id=user.id, success=True)
        .order_by(LoginAttempt.created_at.desc())
        .first()
    )
    last_lockout = (
        Lockout.query.filter_by(user_id=user.id)
        .order_by(Lockout.locked_at.desc())
        .first()
    )
    cutoff = None
    if last_success:
        cutoff = last_success.created_at
    if last_lockout and (cutoff is None or last_lockout.locked_at > cutoff):
        cutoff = last_lockout.locked_at

    query = LoginAttempt.query.filter_by(user_id=user.id, success=False)
    if cutoff:
        query = query.filter(LoginAttempt.created_at > cutoff)
    return query.count()


def register_failure_and_maybe_lock(user: User):
    """
    Call after recording a failed attempt. Applies the adaptive lockout policy
    and returns the newly created Lockout, or None if the threshold wasn't hit.
    """
    cfg = current_app.config
    failures = _consecutive_failures_since_last_reset(user)

    if failures < cfg["MAX_FAILED_ATTEMPTS"]:
        return None

    prior_lockouts = Lockout.query.filter_by(user_id=user.id).count()
    lockout_number = prior_lockouts + 1
    duration = min(
        cfg["BASE_LOCKOUT_SECONDS"] * (cfg["LOCKOUT_BACKOFF_FACTOR"] ** (lockout_number - 1)),
        cfg["MAX_LOCKOUT_SECONDS"],
    )

    lockout = Lockout(
        user_id=user.id,
        lockout_number=lockout_number,
        locked_at=_now(),
        unlock_at=_now() + timedelta(seconds=duration),
        duration_seconds=int(duration),
    )
    db.session.add(lockout)
    db.session.commit()
    return lockout
