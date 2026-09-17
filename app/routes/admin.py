"""
Admin REST endpoints -- power the security dashboard.

  GET  /api/admin/audit-log         - paginated audit trail
  GET  /api/admin/login-attempts    - recent raw login attempts (all users)
  GET  /api/admin/lockouts          - active + historical lockouts
  POST /api/admin/unlock/<user_id>  - manual override to clear an active lockout
  GET  /api/admin/stats             - summary counters for dashboard cards
  GET  /api/admin/verify-audit-log  - recompute the tamper-evident hash chain
                                       and report whether it's intact
"""

import csv
import io
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, g, Response

from app.extensions import db
from app.models import AuditLog, LoginAttempt, Lockout, User
from app.security.decorators import token_required, admin_required
from app.security.audit_logger import log_event, verify_chain

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.route("/audit-log", methods=["GET"])
@token_required(purpose="access")
@admin_required
def audit_log():
    limit = min(int(request.args.get("limit", 50)), 500)
    entries = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()
    return jsonify({"entries": [e.to_dict() for e in entries]}), 200


@admin_bp.route("/audit-log/export", methods=["GET"])
@token_required(purpose="access")
@admin_required
def export_audit_log():
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "id", "user_id", "event_type", "ip_address", "details",
        "created_at", "prev_hash", "hash",
    ])

    entries = AuditLog.query.order_by(AuditLog.id.asc()).all()
    for entry in entries:
        writer.writerow([
            entry.id,
            entry.user_id,
            entry.event_type,
            entry.ip_address,
            entry.details,
            entry.created_at.isoformat(),
            entry.prev_hash,
            entry.hash,
        ])

    return Response(
        output.getvalue(),
        content_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
    )


@admin_bp.route("/login-attempts", methods=["GET"])
@token_required(purpose="access")
@admin_required
def login_attempts():
    limit = min(int(request.args.get("limit", 50)), 500)
    attempts = LoginAttempt.query.order_by(LoginAttempt.created_at.desc()).limit(limit).all()
    return jsonify({
        "attempts": [
            {
                "id": a.id,
                "username_tried": a.username_tried,
                "ip_address": a.ip_address,
                "success": a.success,
                "stage": a.stage,
                "reason": a.reason,
                "created_at": a.created_at.isoformat(),
            }
            for a in attempts
        ]
    }), 200


@admin_bp.route("/lockouts", methods=["GET"])
@token_required(purpose="access")
@admin_required
def lockouts():
    now = datetime.now(timezone.utc)
    rows = Lockout.query.order_by(Lockout.locked_at.desc()).limit(100).all()
    result = []
    for lo in rows:
        unlock_at = lo.unlock_at if lo.unlock_at.tzinfo else lo.unlock_at.replace(tzinfo=timezone.utc)
        result.append({
            "id": lo.id,
            "user_id": lo.user_id,
            "lockout_number": lo.lockout_number,
            "locked_at": lo.locked_at.isoformat(),
            "unlock_at": lo.unlock_at.isoformat(),
            "duration_seconds": lo.duration_seconds,
            "active": unlock_at > now,
        })
    return jsonify({"lockouts": result}), 200


@admin_bp.route("/unlock/<int:user_id>", methods=["POST"])
@token_required(purpose="access")
@admin_required
def manual_unlock(user_id):
    user = User.query.get_or_404(user_id)
    now = datetime.now(timezone.utc)
    active = (
        Lockout.query.filter_by(user_id=user.id)
        .order_by(Lockout.locked_at.desc())
        .first()
    )
    if active:
        active.unlock_at = now
        db.session.commit()
    log_event("manual_unlock", user_id=user.id, details=f"by admin {g.current_user.username}")
    return jsonify({"message": f"User {user.username} unlocked."}), 200


@admin_bp.route("/stats", methods=["GET"])
@token_required(purpose="access")
@admin_required
def stats():
    now = datetime.now(timezone.utc)
    total_users = User.query.count()
    total_attempts = LoginAttempt.query.count()
    failed_attempts = LoginAttempt.query.filter_by(success=False).count()
    active_lockouts = sum(
        1 for lo in Lockout.query.all()
        if (lo.unlock_at if lo.unlock_at.tzinfo else lo.unlock_at.replace(tzinfo=timezone.utc)) > now
    )
    mfa_enabled_users = User.query.filter_by(mfa_enabled=True).count()
    return jsonify({
        "total_users": total_users,
        "total_login_attempts": total_attempts,
        "failed_login_attempts": failed_attempts,
        "active_lockouts": active_lockouts,
        "mfa_enabled_users": mfa_enabled_users,
    }), 200


@admin_bp.route("/verify-audit-log", methods=["GET"])
@token_required(purpose="access")
@admin_required
def verify_audit_log():
    is_intact, broken_at_id = verify_chain()
    return jsonify({
        "intact": is_intact,
        "broken_at_entry_id": broken_at_id,
        "message": (
            "Audit log chain is intact -- no tampering detected."
            if is_intact
            else f"Chain integrity broken at entry id={broken_at_id}. "
                 "This entry (or one before it) was likely altered outside the application."
        ),
    }), 200