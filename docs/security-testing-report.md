# MLPSAPS — Security Testing Report

## What Was Tested

Two layers of testing validate the system's security controls:

1. **Automated test suite** — 25 pytest tests covering registration, password
   policy enforcement, password history reuse blocking, adaptive lockout
   backoff math, the full MFA enrollment/verification flow, JWT session
   issuance and refresh, admin access control, and the audit log.
2. **Live brute-force simulation** — run via the project's own CLI
   demonstration tool (`cli_demo.py simulate-lockout`), which repeatedly
   submits wrong-password login attempts against a real account and
   observes the system's actual response in real time, rather than relying
   only on unit-test assertions.

## Automated Test Results

```
25 passed in 2.03s
```

All 25 tests pass with no failures. Coverage includes:
- Registration input validation and password policy rejection
- Password history (last 5) reuse blocking on password change
- Lockout duration doubling on repeat offenses, capped at 1 hour
- Lockout auto-expiry and admin manual-unlock
- Full MFA flow: TOTP enrollment, QR provisioning, confirmation, recovery codes
- JWT access/refresh token issuance and validation
- Admin-only route protection (non-admins correctly rejected)
- Audit log entries created for security-relevant events

## Brute-Force Simulation Results

Running the CLI tool's `simulate-lockout` command against a live test
account produced the following observed behavior:

| Round | Failed attempts | Result | Lockout duration |
|---|---|---|---|
| 1 | 5 | Account locked | 30 seconds |
| 2 | 5 | Account locked | 60 seconds |
| 3 | 5 | Account locked | 120 seconds |

Each round submitted 5 consecutive wrong-password attempts (the configured
threshold), and the system correctly locked the account each time,
doubling the lockout duration on each repeat offense — exactly matching the
adaptive backoff design described in `SECURITY.md`. All wrong attempts
returned HTTP 401 individually, with the account transitioning to a locked
state only after the threshold was reached, confirming the lockout logic
triggers on attempt count rather than on a single failure.

## What This Demonstrates

- The password policy engine rejects weak and breach-listed passwords
  before any hash is stored, verified both by unit tests and by live
  registration attempts during manual testing.
- The brute-force guard is not just a database flag — it produces a real,
  observable delay that scales with repeat offenses, which is the core
  defense against automated credential-stuffing and password-guessing
  attacks.
- MFA and session handling are exercised end-to-end by the automated suite,
  not just at the unit level, giving confidence the full staged-login flow
  (password → pre-MFA token → TOTP → full session) works as designed.
- Admin-only actions (viewing the audit log, manually unlocking accounts)
  are correctly gated and were verified live through the admin dashboard
  in addition to the automated access-control tests.

## Notes for Reviewers

This report reflects testing performed against the local development
environment using SQLite. The 25 automated tests are re-run automatically
on every change to catch regressions before merging to `main`, per the
team's pull-request workflow described in `TEAM_REPO_GUIDE.md`.
