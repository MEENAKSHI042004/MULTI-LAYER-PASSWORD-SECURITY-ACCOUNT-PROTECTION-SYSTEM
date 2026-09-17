"""Terminal demo for the application's core authentication security flows."""

import argparse
from datetime import datetime, timedelta, timezone
import sys

from app import create_app
from app.extensions import db
from app.models import Lockout, User
from app.routes.auth import login as auth_login
from app.routes.auth import register as auth_register
from app.security.brute_force import get_active_lockout
from config import Config

DEFAULT_USERNAME = "cli_demo_user"
DEFAULT_EMAIL = "cli_demo@example.com"
DEFAULT_PASSWORD = "Str0ng!Passw0rd"
DEFAULT_WRONG_PASSWORD = "Wrong!Password123"


class DemoConfig(Config):
    """Keep endpoint rate limits from hiding the lockout escalation demo."""

    RATELIMIT_ENABLED = False


def _response_from(view, app, path, payload):
    """Call an existing Flask view directly, without sending an HTTP request."""
    with app.test_request_context(path, method="POST", json=payload):
        return app.make_response(view())


def _response_json(response):
    return response.get_json(silent=True) or {}


def _print_response(response):
    data = _response_json(response)
    print(f"  Status: {response.status_code}")
    if data:
        for key, value in data.items():
            if key not in {"access_token", "refresh_token", "pre_mfa_token"}:
                print(f"  {key}: {value}")


def register_user(app, args):
    print("[1/2] Registering test user...")
    print(f"  Username: {args.username}")
    print(f"  Email: {args.email}")
    response = _response_from(
        auth_register,
        app,
        "/api/auth/register",
        {"username": args.username, "email": args.email, "password": args.password},
    )
    _print_response(response)
    if response.status_code == 201:
        print("Registration completed successfully.")
        return 0
    print("Registration did not complete.")
    return 1


def login_user(app, args):
    print("[1/1] Attempting login...")
    print(f"  Username: {args.username}")
    response = _response_from(
        auth_login,
        app,
        "/api/auth/login",
        {"username": args.username, "password": args.password},
    )
    _print_response(response)
    if response.status_code == 200:
        print("Login succeeded.")
        return 0
    print("Login was rejected by the security controls.")
    return 1


def simulate_lockout(app, args):
    with app.app_context():
        user = User.query.filter_by(username=args.username).first()
        if not user:
            print(f"No user named '{args.username}' exists. Register one first.", file=sys.stderr)
            return 1

        print(f"Simulating lockouts for '{args.username}' with repeated wrong passwords.")
        print(f"Configured threshold: {app.config['MAX_FAILED_ATTEMPTS']} failed attempts")
        print(f"Rounds to demonstrate: {args.rounds}")

        for round_number in range(1, args.rounds + 1):
            print(f"\nRound {round_number}: sending wrong-password attempts...")
            for attempt_number in range(1, app.config["MAX_FAILED_ATTEMPTS"] + 1):
                response = _response_from(
                    auth_login,
                    app,
                    "/api/auth/login",
                    {"username": args.username, "password": args.password},
                )
                data = _response_json(response)
                print(f"  Attempt {attempt_number}: status {response.status_code}")

                lockout = Lockout.query.filter_by(user_id=user.id).order_by(Lockout.locked_at.desc()).first()
                if lockout and lockout.lockout_number >= round_number:
                    print(
                        f"  Account locked: lockout #{lockout.lockout_number}, "
                        f"duration {lockout.duration_seconds} seconds."
                    )
                    break
                if response.status_code == 423:
                    print(f"  Account is already locked ({data.get('retry_after_seconds', 0)} seconds remaining).")
                    break

            lockout = Lockout.query.filter_by(user_id=user.id).order_by(Lockout.locked_at.desc()).first()
            if not lockout or lockout.lockout_number < round_number:
                print("  The account did not reach the lockout threshold.", file=sys.stderr)
                return 1

            if round_number < args.rounds:
                print("  Expiring this demo lockout so the next backoff round can be shown immediately.")
                lockout.unlock_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                db.session.commit()

        final_lockout = get_active_lockout(user)
        if final_lockout:
            print(
                f"\nSimulation complete. The account remains locked for "
                f"approximately {final_lockout.duration_seconds} seconds."
            )
        else:
            print("\nSimulation complete. The final demo lockout has expired.")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="Demonstrate MLPSAPS authentication and account-lockout flows in-process."
    )
    subparsers = parser.add_subparsers(dest="command", title="commands")

    register_parser = subparsers.add_parser("register", help="create a test user")
    register_parser.add_argument("--username", default=DEFAULT_USERNAME)
    register_parser.add_argument("--email", default=DEFAULT_EMAIL)
    register_parser.add_argument("--password", default=DEFAULT_PASSWORD)

    login_parser = subparsers.add_parser("login", help="attempt login with credentials")
    login_parser.add_argument("--username", required=True)
    login_parser.add_argument("--password", required=True)

    lockout_parser = subparsers.add_parser(
        "simulate-lockout", help="demonstrate escalating lockout durations"
    )
    lockout_parser.add_argument("--username", required=True)
    lockout_parser.add_argument("--password", default=DEFAULT_WRONG_PASSWORD, help=argparse.SUPPRESS)
    lockout_parser.add_argument("--rounds", type=int, default=3, choices=range(1, 20))

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0

    app = create_app(DemoConfig)
    if args.command == "register":
        return register_user(app, args)
    if args.command == "login":
        return login_user(app, args)
    return simulate_lockout(app, args)


if __name__ == "__main__":
    raise SystemExit(main())
