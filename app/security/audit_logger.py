"""
Security Audit Logging Module.

Every security-relevant event (registration, login success/failure, lockout,
MFA enrolment/verification, password change, admin actions) is written to the
AuditLog table. This gives the dashboard and the admin API a tamper-evident-ish
(append-only, never updated) trail for the security-testing report.
"""

from app.extensions import db
from app.models import AuditLog


def log_event(event_type: str, ip_address: str = None, user_id: int = None, details: str = None):
    entry = AuditLog(
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address,
        details=details,
    )
    db.session.add(entry)
    db.session.commit()
    return entry
