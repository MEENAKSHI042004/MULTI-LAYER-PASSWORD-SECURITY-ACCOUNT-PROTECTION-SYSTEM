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
- **Common-password rejection** — length/complexity rules alone don't stop
  someone from choosing `Password1!`, which is both "compliant" and among the
  first entries any attacker's dictionary tries. The demo ships a small
  illustrative list; a production deployment would check against the full
  "Have I Been Pwned" Pwned Passwords corpus via its k-anonymity API (only a
  hash prefix is sent, so the real password is never transmitted to a third
  party).
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

**Trade-off acknowledged:** because JWTs are stateless, `logout` cannot
"revoke" an access token server-side in this minimal build — it relies on the
client discarding it and the token's own short expiry. A production
extension would add a denylist of revoked token IDs (`jti`) checked on each
request, noted as a comment in `routes/auth.py`.

---

## 6. Rate Limiting

**Why in addition to account lockout:** lockout protects a *specific known
account*; rate limiting protects the *endpoint itself* against high-volume
traffic (e.g. username enumeration sweeps across many accounts, or basic
denial-of-service). `Flask-Limiter` enforces per-IP limits: 10 login attempts
per minute, 5 registrations per hour, 100 general requests per hour by
default (`config.py`).

---

## 7. Security Audit Logging

Every security-relevant event — registration, password success/failure,
lockouts, MFA enrolment/verification, password changes, admin unlocks — is
written to an append-only `AuditLog` table (`security/audit_logger.py`) and
surfaced in the dashboard. Raw `LoginAttempt` rows are kept separately from
the higher-level `AuditLog` narrative so the brute-force module can do fast
counting queries without scanning free-text log entries.

---

## 8. Known Limitations (be upfront about these in the viva)

- No token revocation list yet for JWTs (see §5).
- The common-password list is illustrative, not the full breach corpus.
- SQLite is used for the demo; `DATABASE_URL` can point at PostgreSQL for a
  production-shaped deployment (SQLAlchemy makes this a config change, not a
  code change).
- TLS termination is expected to be handled by a reverse proxy (nginx/Caddy)
  in front of the container — the app itself serves plain HTTP, matching how
  Gunicorn deployments are normally fronted.
- The email-OTP alternative mentioned in early planning was intentionally
  narrowed to TOTP-only for this build, since TOTP doesn't depend on a
  working SMTP relay for the demo to function offline.
