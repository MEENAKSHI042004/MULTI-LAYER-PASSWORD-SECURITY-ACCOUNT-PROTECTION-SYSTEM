"""Shared orchestration for demonstrating the adaptive lockout policy."""

from datetime import datetime, timedelta, timezone

from flask import current_app

from app.extensions import db
from app.models import Lockout, User
from app.security.brute_force import get_active_lockout


def run_lockout_simulation(user: User, attempt_login, rounds=3):
    """Run bounded lockout rounds through an attempt callback and return log events."""
    threshold = current_app.config["MAX_FAILED_ATTEMPTS"]
    previous_lockouts = Lockout.query.filter_by(user_id=user.id).count()
    events = []

    for round_number in range(1, rounds + 1):
        expected_lockout = previous_lockouts + round_number
        events.append({
            "type": "round",
            "round": round_number,
            "message": f"Round {round_number}: sending up to {threshold} failed attempts.",
        })

        for attempt_number in range(1, threshold + 1):
            status, body = attempt_login()
            events.append({
                "type": "attempt",
                "round": round_number,
                "attempt": attempt_number,
                "status": status,
                "message": f"Round {round_number}, attempt {attempt_number}: status {status}.",
            })

            latest_lockout = (
                Lockout.query.filter_by(user_id=user.id)
                .order_by(Lockout.locked_at.desc())
                .first()
            )
            if latest_lockout and latest_lockout.lockout_number >= expected_lockout:
                events.append({
                    "type": "lockout",
                    "round": round_number,
                    "lockout_number": latest_lockout.lockout_number,
                    "duration_seconds": latest_lockout.duration_seconds,
                    "message": (
                        f"Account locked: lockout #{latest_lockout.lockout_number}, "
                        f"duration {latest_lockout.duration_seconds} seconds."
                    ),
                })
                break

            if status == 423:
                events.append({
                    "type": "locked",
                    "round": round_number,
                    "message": (
                        "Account was already locked "
                        f"({body.get('retry_after_seconds', 0)} seconds remaining)."
                    ),
                })
                break

        latest_lockout = (
            Lockout.query.filter_by(user_id=user.id)
            .order_by(Lockout.locked_at.desc())
            .first()
        )
        if not latest_lockout or latest_lockout.lockout_number < expected_lockout:
            events.append({
                "type": "error",
                "round": round_number,
                "message": "The account did not reach the lockout threshold.",
            })
            return events, False

        if round_number < rounds:
            latest_lockout.unlock_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.session.commit()
            events.append({
                "type": "reset",
                "round": round_number,
                "message": "Expired this demo lockout so the next backoff round can run.",
            })

    active_lockout = get_active_lockout(user)
    if active_lockout:
        message = (
            "Simulation complete. The test account remains locked for "
            f"approximately {active_lockout.duration_seconds} seconds."
        )
    else:
        message = "Simulation complete. The final test lockout has expired."
    events.append({"type": "complete", "message": message})
    return events, True