# Limitations & Production Path

MLPSAPS is built and validated as a course-project authentication provider:
layered defences, adversarially tested, with a second site (the demo
storefront) authenticating through it. This page lists, honestly, what is
**not** production-grade yet and what the production version would do instead.
Each item was checked against the code, not written from memory.

For design rationale see `SECURITY.md`; for run/deploy steps see `DEPLOYMENT.md`.

## Account lifecycle

| Gap | Today | Production path |
|---|---|---|
| No password reset or email verification | There is no self-service reset. Email-OTP was deliberately dropped so the demo works offline (`SECURITY.md` §8). MFA users have single-use recovery codes. | Signed, single-use, short-lived reset/verification tokens delivered through an SMTP provider; rate-limit the endpoints; don't reveal whether an address exists. |
| Seeded admin has a fallback password | If `SEED_ADMIN_PASSWORD` is unset, the admin is created with a hard-coded default. | Refuse to start outside test/dev when it is unset; force a password change on first login. |
| Breach check is skipped when the service is unreachable | Passwords are checked against Have I Been Pwned using the k-anonymity range API. If that service cannot be reached, registration still enforces the length and complexity rules and a short local list, but it cannot check for breached passwords. Setting `BREACH_CHECK_FAIL_CLOSED=true` makes registration refuse passwords instead when the check cannot run. | Run fail-closed by default in production, and keep a larger local breach list or a self-hosted copy of the range data as a backup. |

## Secrets and cryptography

| Gap | Today | Production path |
|---|---|---|
| TOTP secrets are stored in plaintext in the database | Password hashes (Argon2id) and recovery codes (hashed) are protected; the TOTP seed column is not encrypted. A database leak would expose seeds. | Encrypt the column with a key held outside the database (envelope encryption / KMS, or at minimum an env-supplied Fernet key). |
| Secrets live in environment variables | Rotation is supported for JWTs (`JWT_SECRET_KEY_PREVIOUS`) but is manual. | A secrets manager with automated rotation. |
| JWTs are HS256 (shared secret) | Only MLPSAPS can verify a token, so the storefront calls `/api/auth/me` to check one. That also gives instant revocation. | Asymmetric signing (RS256/EdDSA) published via JWKS so relying sites can verify offline, keeping a short TTL plus revocation checks. |

## Transport and web hardening

| Gap | Today | Production path |
|---|---|---|
| TLS is not terminated by the app | The container serves plain HTTP behind a reverse proxy (`force_https=False`, secure-cookie flag off). The app runs under Gunicorn, not the dev server. | Keep TLS at nginx/Caddy/the platform; if the app ever serves TLS itself, turn on `force_https` and secure cookies. |
| CSP allows inline styles | Scripts are locked to `'self'`; `style-src` includes `'unsafe-inline'`. | Move inline styles to files or use nonces, then drop `'unsafe-inline'`. |
| Client keeps the JWT in `sessionStorage` | Readable by any XSS on the storefront. Mitigated by tab-scoped storage, a 15-minute access token and server-side revocation. | `httpOnly` cookie with CSRF protection (backend-for-frontend), or a standard OIDC flow. |
| Integration is custom, not a standard protocol | The storefront calls bespoke `/api/auth/*` endpoints. | Implement OpenID Connect (authorization-code flow with PKCE) so any compliant client can integrate. |

## Scale and operations

| Gap | Today | Production path |
|---|---|---|
| Rate-limit counters are per worker | `memory://` storage with 2 Gunicorn workers makes effective limits looser than configured. Account lockout is unaffected because it is stored in the database. | Redis via `RATELIMIT_STORAGE_URI`. |
| No schema migrations | Tables are created with `create_all()`; there is no Alembic/Flask-Migrate, so schema changes need manual handling. | Add Alembic migrations before any real data exists. |
| Database | SQLite by default for development. PostgreSQL is supported and was tested end-to-end (`SECURITY.md` §9), including a race condition that testing found and fixed. | PostgreSQL with backups; a managed free tier may expire. |
| Audit log has no alerting | The log is hash-chained and tamper-evident, with CSV/PDF export, but nothing alerts on suspicious events. | Ship events to a SIEM and alert on lockout spikes and chain-verification failures. |
| Load-test numbers are from a development machine | `docs/load-testing.md` is evidence the limiter behaves under concurrency, not capacity planning. | Re-run against production-shaped infrastructure. |

## Passwordless (WebAuthn)

- Verified with Chromium's virtual authenticator, including the cross-site case
  (enrol on the dashboard, sign in from the storefront). Also tested end to
  end with a real Chrome passkey (synced through Google Password Manager) on a
  physical laptop, including signing in on the storefront with a key enrolled
  on the dashboard. **Windows Hello and a physical USB security key have not
  been tested.**
- An RP ID must be the page's host or a registrable parent of it. Passwordless
  across two sites therefore needs them on subdomains of one domain you control
  (e.g. `auth.example.com` and `shop.example.com`); two default
  `onrender.com` hosts cannot share one.

## What this does *not* claim

It does not claim to be a drop-in replacement for an established identity
provider. The point of the project is to show, with evidence, that the
layered defences work together and that a second site can rely on them.