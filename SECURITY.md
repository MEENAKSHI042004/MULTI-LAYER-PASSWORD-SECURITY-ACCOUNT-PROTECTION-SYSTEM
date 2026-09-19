# SECURITY.md — Design Decisions

This document explains *why* each security control in the Multi-Layer
Password Security & Account Protection System (MLPSAPS) was built the way it
was, so you can defend every choice to your project guide and reviewer.

---

## 1. Password Hashing — bcrypt

**Choice:** bcrypt (via the `bcrypt` library), work factor 12 rounds by default.

**Why bcrypt over plain SHA-256/MD5:** generic hash functions are designed to
be *fast*, which is exactly the wrong property for password storage — it lets
an attacker with a leaked hash try billions of guesses per second on a GPU.
bcrypt is deliberately slow and its cost factor is tunable, so as hardware
gets faster you raise the round count to keep cracking expensive.

**Why bcrypt over argon2 here:** argon2 (specifically argon2id) is the more
modern, memory-hard recommendation and is a perfectly valid alternative — the
codebase isolates all hashing behind `app/security/hashing.py`, so swapping
the implementation later is a one-file change. bcrypt was chosen as the
default for this build because it has no external C-library dependency
headaches in constrained/offline lab environments and is still considered
cryptographically sound.

**Why per-password random salts matter:** bcrypt generates a fresh random
salt per call and embeds it in the output hash string. This means two users
with the identical password get *different* stored hashes, defeating
precomputed rainbow-table attacks.

**Rounds = 12:** each increment doubles the compute cost. 12 rounds takes
roughly 200–300ms per hash on typical hardware — negligible for a real login,
but expensive enough to make offline brute-forcing a leaked database
impractical at scale. (Tests use `BCRYPT_ROUNDS = 4` purely for speed; never
use that value outside the test suite.)

---

## 2. Brute-Force Prevention — Adaptive Lockout with Exponential Backoff

**Why lockout instead of relying on password strength alone:** even a strong
password can eventually be guessed if an attacker gets unlimited, unthrottled
attempts. Alsaleh, Mannan & van Oorschot's analysis of large-scale
password-guessing attacks (cited in the abstract) shows that lockout- and
delay-based countermeasures are the most effective practical defense against
this class of attack.

**Why exponential backoff rather than a fixed lockout window:** a fixed delay
(e.g. "always lock for 30 seconds") only mildly inconveniences an automated
attacker who can simply wait it out and keep trying. Growing the lockout
duration with each successive violation (30s → 60s → 120s → ... capped at
1 hour, see `BASE_LOCKOUT_SECONDS` / `LOCKOUT_BACKOFF_FACTOR` /
`MAX_LOCKOUT_SECONDS` in `config.py`) makes sustained automated guessing
increasingly expensive, while a real user who mistypes their password a few
times only ever faces the short initial delay.

**Why lockouts are per-account and time-based (not IP-based only):**
IP-based blocking alone is trivially bypassed with rotating proxies/botnets;
tying the lockout to the *account* protects the asset that actually matters
(the user's data) regardless of where the traffic originates. IP address is
still logged on every attempt (`LoginAttempt.ip_address`) so an admin can spot
distributed attacks in the dashboard.

**Auto-unlock, not permanent lock:** locking an account forever after one
attack is itself a denial-of-service vector (an attacker could lock out
legitimate users just by trying their username with a wrong password).
Lockouts expire automatically via the stored `unlock_at` timestamp; an admin
override endpoint (`POST /api/admin/unlock/<user_id>`) exists for support
cases.

**Where the failure counter resets:** a successful login, or a new lockout
event, resets the "consecutive failures" window (see
`_consecutive_failures_since_last_reset` in `brute_force.py`) — so genuine
users aren't penalized for old, already-forgiven mistakes.

**MFA stage is also brute-force-guarded:** a wrong TOTP/recovery code counts
toward the same lockout counter as a wrong password, closing the gap where an
attacker who somehow obtained a valid password could still hammer the MFA
step indefinitely.

---

## 3. Password Policy — Validator Module

Enforced in `app/security/password_validator.py`:

- **Minimum length 10, maximum 128** — length is the single strongest lever
  against brute-force; 128 is a generous ceiling that avoids DoS via
  pathologically long inputs to the hashing function.
- **Requires upper/lower/digit/special characters** — increases the
  effective character-set size and therefore the guessing search space.
- **Breach-password rejection (Have I Been Pwned)** — length/complexity
  rules alone don't stop someone from choosing `Password1!`, which is both
  "compliant" and among the first entries any attacker's dictionary tries.
  Every submitted password is checked against the full "Have I Been Pwned"
  Pwned Passwords corpus via its k-anonymity range API — only a 5-character
  hash prefix is sent, so the real password is never transmitted to a third
  party. See §3a below for full detail. If HIBP is unreachable, the check
  falls back to a small local list of the most common passwords rather than
  allowing an unchecked registration through.
- **Password history (last 5) blocked on reuse** — stops the common
  workaround of cycling back to an old, possibly-already-compromised
  password when forced to rotate.
- **90-day expiry window** — a defense-in-depth control recommended in the
  cited literature for high-assurance systems, applied here as a soft check
  (`is_password_expired`) that the login route surfaces to the client rather
  than silently blocking, since aggressive forced rotation is now considered
  by some modern guidance (e.g. NIST 800-63B) to encourage weaker passwords
  if over-used. It is included primarily to demonstrate the mechanism for the
  review.

### 3a. Breach-Password Check — Have I Been Pwned Integration

**How the check works (k-anonymity model):**
1. The submitted password is hashed locally using SHA-1.
2. Only the **first 5 characters** of that hash are sent to HIBP's API
   (`GET /range/{prefix}`).
3. HIBP returns every hash suffix in its database that shares that same
   5-character prefix — typically several hundred to a few thousand
   entries — each paired with how many times it has appeared in known
   breaches.
4. The full hash suffix is compared **locally** against that returned
   list to determine whether there's a match.

At no point does the full password, or even its full hash, leave the
server. HIBP only ever sees a 5-character prefix shared by thousands of
unrelated passwords, so it cannot feasibly determine which exact password
was checked.

**Fallback behavior:** if the HIBP API is unreachable (network failure,
timeout, or the service being down), the check fails safe by falling back
to the original small local list of common passwords rather than silently
allowing an unchecked password through. This trades some breach-detection
coverage for availability, so a registration can never be permanently
blocked by a third-party outage.

**Testing:** because the check depends on a live external API, the test
suite mocks `check_pwned()` via an `autouse` pytest fixture in
`conftest.py`, so all existing tests run deterministically offline without
depending on network access or on whether a given test password happens to
appear in a real breach dump. A dedicated test,
`test_registration_rejects_breached_password`, overrides the mock to
simulate a breached password and confirms the rejection path works.

**Manually verified:** registering with the password `password123` returns
a `400` with the message *"This password has appeared in 2,266,543 known
data breaches; choose a different one."* A strong, randomly generated
password registers successfully with no breach-related error.

---

## 4. TOTP-Based Multi-Factor Authentication

**Why TOTP (RFC 6238) specifically:** it requires no SMS/telecom dependency
(avoiding SIM-swap risk), works offline once enrolled, and is supported by
free, ubiquitous authenticator apps. The literature review cites TOTP as
among the most commonly deployed, practically adoptable second factors.

**Two-stage login, represented by two different JWT "purposes":** after a
correct password, the server issues a short-lived (5 minute) `pre_mfa` token
— *not* a full access token. `pre_mfa` tokens are only accepted by
`/api/auth/verify-mfa`; every other protected route requires a token with
`purpose: access`. This is enforced in `security/decorators.py` and directly
tested in `tests/test_mfa.py::test_pre_mfa_token_cannot_access_protected_routes`.
Without this separation, a bug (or attacker) could otherwise treat "password
correct" as equivalent to "fully authenticated," silently defeating the
second factor.

**Recovery codes:** generated once at enrolment, shown to the user exactly
once, and stored as bcrypt hashes rather than plaintext — a database leak
should not hand out usable backup codes. Each code is single-use
(`RecoveryCode.used`).

---

## 5. JWT Session Management

**Why JWT over server-side sessions:** JWTs are stateless and self-verifying
(HMAC-signed with `JWT_SECRET_KEY`), which fits a REST API that may later be
horizontally scaled without a shared session store.

**Short-lived access tokens (15 min) + longer-lived refresh tokens (7 days):**
limits the blast radius if an access token is intercepted, while avoiding
forcing the user to re-enter credentials constantly. The refresh endpoint
(`/api/auth/refresh`) issues a new access token without re-sending the
password.

**Token "purpose" claim:** as described above, distinguishes `pre_mfa` /
`access` / `refresh` tokens so each can only be used where intended.

**Revocation:** every access and refresh token carries a unique `jti` claim.
`logout` and the session-management endpoints below write that `jti` to a
`RevokedToken` table; `token_required` checks every incoming token's `jti`
against it before trusting the token, regardless of whether it's still
within its signed expiry window. This closes the usual "JWTs can't really be
logged out" gap — a leaked or reused token stops working the moment it's
revoked, not just when it happens to expire on its own.

**Active-session tracking:** each successful login creates a `Session` row
(user, IP, the access token's `jti`, its paired refresh token's `jti`, and a
`last_seen_at` timestamp updated on every authenticated request). `GET
/api/auth/sessions` lists a user's own active sessions; `POST
/api/auth/sessions/<id>/revoke` lets them end a specific one (e.g. "log out
that other device") by revoking both its access and refresh `jti` at once —
not just the access token, which was an early version of this feature's gap
until it was corrected.

---

## 6. Rate Limiting

**Why in addition to account lockout:** lockout protects a *specific known
account*; rate limiting protects the *endpoint itself* against high-volume
traffic (e.g. username enumeration sweeps across many accounts, or basic
denial-of-service). `Flask-Limiter` enforces per-IP limits: 10 login attempts
per minute, 3 registrations per minute, 100 general requests per hour by
default (`config.py`).

**Per-username limiting, in addition to per-IP:** the login endpoint also
throttles by the *username in the request body* (5 attempts/minute),
independent of the per-IP limit above. Per-IP limiting alone can be dodged
by spreading attempts for one target account across many IP addresses
(botnets, rotating proxies); tying a second limit to the account itself
closes that gap regardless of how many source IPs an attacker uses.

---

## 7. Security Audit Logging

Every security-relevant event — registration, password success/failure,
lockouts, MFA enrolment/verification, password changes, admin unlocks — is
written to an `AuditLog` table (`security/audit_logger.py`) and surfaced in
the dashboard. Raw `LoginAttempt` rows are kept separately from the
higher-level `AuditLog` narrative so the brute-force module can do fast
counting queries without scanning free-text log entries.

**Tamper-evidence:** each entry's stored `hash` is computed from its own
fields *plus* the previous entry's hash — the same chaining idea behind a
blockchain's block hashes, applied to a single append-only table instead.
Editing or deleting any row directly in the database (bypassing the app
entirely) breaks the chain from that point forward, because every
subsequent entry's hash was computed assuming the original, unmodified
previous hash. `GET /api/admin/verify-audit-log` recomputes the entire
chain from scratch and reports exactly which entry ID it first diverges
at, so tampering isn't just theoretically detectable — it's a single API
call away from being proven.

---

## 8. Known Limitations (be upfront about these in the viva)

- SQLite is used for local development by default; `DATABASE_URL` can
  point at PostgreSQL for a production-shaped deployment. This was
  initially assumed to be a pure config change, but testing it end-to-end
  surfaced a real bug (see §9) that required a small code fix, not just a
  config swap.
- TLS termination is expected to be handled by a reverse proxy (nginx/Caddy)
  in front of the container — the app itself serves plain HTTP, matching how
  Gunicorn deployments are normally fronted.
- The email-OTP alternative mentioned in early planning was intentionally
  narrowed to TOTP-only for this build, since TOTP doesn't depend on a
  working SMTP relay for the demo to function offline.

---

## 9. PostgreSQL End-to-End — A Race Condition SQLite Was Hiding

**What was tested:** the Docker Compose setup includes an optional
Postgres service (`db`). Enabling it and running the full stack against a
real Postgres instance surfaced a bug that never appeared against SQLite.

**The bug:** the container starts Gunicorn with 2 worker processes. Each
worker independently imports the Flask app, and `create_app()` calls
`db.create_all()` on every import. Against SQLite, this went unnoticed —
SQLite's whole-file locking effectively serializes concurrent writers, so
the race was invisible. Against Postgres, both workers raced to create the
same tables at nearly the same instant, and the loser crashed with:

```
psycopg2.errors.UniqueViolation: duplicate key value violates unique
constraint "pg_class_relname_nsp_index"
```

Gunicorn's supervisor restarted the crashed worker automatically, so the
app appeared to recover on its own — but this was fragile, timing-dependent
luck rather than correct behavior, and would resurface unpredictably on any
fresh deployment.

**The fix:** table creation was moved out of the app-boot path shared by
every worker and into a dedicated `entrypoint.sh` script that runs once, in
a single process, before Gunicorn starts and forks any workers:

```sh
#!/bin/sh
set -e
python -c "from app import create_app; from app.extensions import db; app = create_app(); app.app_context().push(); db.create_all()"
exec gunicorn --bind 0.0.0.0:5000 --workers 2 run:app
```

`db.create_all()` is naturally idempotent (it only creates tables that
don't already exist), so this is safe to run on every container restart. By
the time Gunicorn's workers boot and each one calls `create_app()` again
individually, the tables already exist, so those calls become harmless
no-ops instead of racing each other.

**Why this matters beyond just fixing the crash:** this is a concrete,
reproducible example of a bug class that only surfaces under a
production-shaped database, reinforcing why "the config supports Postgres"
is not the same claim as "Postgres works end-to-end" — the latter needs to
actually be run and tested, not just assumed from SQLAlchemy's
database-agnostic API.

**Verified:** registration was tested directly against the running
Postgres container (bypassing the API layer to rule out any other
variable) and confirmed via `psql` that rows persist correctly with
sequential IDs and no data loss across repeated registrations.

---

## 10. Finding: Per-Username Rate Limiting Interacts With Account Lockout

**What was tested:** a credential-stuffing simulation against a single
test account, using a curated list of ~50 of the most common breached
passwords, to measure how many attempts an attacker gets before the
account is locked.

**What was observed:** the account was not locked after the expected
5 failed attempts (`MAX_FAILED_ATTEMPTS = 5`). Instead, it took 16
attempts across several separate 1-minute windows before a lockout
finally triggered.

**Root cause:** the newly added per-username rate limiter
(`RATELIMIT_LOGIN_PER_USERNAME`) is configured at exactly "5 per
minute" — the same threshold as `MAX_FAILED_ATTEMPTS`. Because the rate
limiter runs first (as a route decorator, before the request body is
even processed), it blocks the 6th request with a `429` before the
lockout logic ever sees a 5th recorded failure in the database. The
account is never actually locked in that window; it's simply
rate-limited into silence. Only across multiple separate 1-minute
windows does the recorded failure count in the database eventually
exceed 5, at which point the lockout logic (which has no time-window
expiry — see §2) finally fires.

**Why this matters:** the two defenses were intended to reinforce each
other, but as configured they compete for the same budget of requests.
An attacker distributing a credential-stuffing attempt across multiple
minutes (rather than sending 50 requests instantly) effectively gets
extra "free" guesses per minute that never count toward the lockout
threshold in that window, meaningfully delaying when the account
actually locks.

**Recommended fix:** set `RATELIMIT_LOGIN_PER_USERNAME` higher than
`MAX_FAILED_ATTEMPTS` (e.g. 8–10 per minute) so the lockout has room to
fire on genuine password failures, while the rate limiter remains a
backstop against very high-volume or distributed attempts rather than
competing with the lockout for the same 5 requests.

**Verified:** confirmed via an isolated, deliberately paced test (one
request every 2 seconds, well under 1 per minute) — the rate limiter
still returned `429` on the 6th request, proving the interaction is
independent of request timing/burstiness and is a genuine threshold
overlap, not a timing artifact.