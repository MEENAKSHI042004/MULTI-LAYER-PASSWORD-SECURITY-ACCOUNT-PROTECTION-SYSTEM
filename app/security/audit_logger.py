"""
Security Audit Logging Module.

Every security-relevant event (registration, login success/failure, lockout,
MFA enrolment/verification, password change, admin actions) is written to the
AuditLog table.

Tamper-evident chain: each entry's hash is calculated from its own fields PLUS
the hash of the entry immediately before it (like a mini blockchain). If anyone
edits or deletes a row directly in the database, recalculating hashes forward
from that point will no longer match what's stored -- verify_chain() below
detects exactly where the chain breaks.
"""

import hashlib
from datetime import timezone

from app.extensions import db
from app.models import AuditLog


def _iso(dt):
    """Normalize a datetime to always include UTC timezone info before formatting,
    since SQLite can hand timestamps back without tzinfo attached -- without this,
    the same moment in time could produce two different-looking hashes."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _compute_hash(entry: AuditLog) -> str:
    """Combine this entry's own data with the previous entry's hash, then hash
    all of it together. Changing ANY field here, on ANY past entry, produces a
    different hash -- which is what makes tampering detectable."""
    raw = "|".join([
        str(entry.id),
        str(entry.user_id),
        entry.event_type,
        str(entry.ip_address),
        str(entry.details),
        _iso(entry.created_at),
        str(entry.prev_hash),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def log_event(event_type: str, ip_address: str = None, user_id: int = None, details: str = None):
    last_entry = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev_hash = last_entry.hash if last_entry else None

    entry = AuditLog(
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address,
        details=details,
        prev_hash=prev_hash,
        hash="pending",  # placeholder so the NOT NULL constraint doesn't block the flush below
    )
    db.session.add(entry)
    db.session.flush()  # assigns entry.id and created_at, needed to compute the real hash

    entry.hash = _compute_hash(entry)
    db.session.commit()
    return entry


def verify_chain():
    """Walk every entry in id order and recompute each hash from scratch.
    Returns (is_intact: bool, broken_at_id: int | None)."""
    entries = AuditLog.query.order_by(AuditLog.id.asc()).all()
    expected_prev_hash = None

    for entry in entries:
        if entry.prev_hash != expected_prev_hash:
            return False, entry.id
        if _compute_hash(entry) != entry.hash:
            return False, entry.id
        expected_prev_hash = entry.hash

    return True, None