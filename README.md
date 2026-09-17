# Multi-Layer Password Security & Account Protection System (MLPSAPS)

VTU Major Project — Phase 2 implementation. See `SECURITY.md` for the design
rationale behind every control (hashing, lockout, MFA, JWT, rate limiting).

## What this is

A working Flask REST API + web dashboard implementing:

- **Password Hashing Module** — bcrypt, per-password random salt
- **Password Validator** — length/complexity/breach-list policy, history reuse block
- **Brute-Force Prevention** — adaptive account lockout with exponential backoff
- **Security Audit Logging** — append-only event log + raw attempt log
- **TOTP MFA** — QR-code enrolment, verification, single-use recovery codes
- **JWT Session Management** — short-lived access + refresh tokens, staged pre-MFA token
- **Rate Limiting** — per-IP throttling on register/login via Flask-Limiter
- **Security Dashboard** — live audit log, login attempts, and lockout table (admin only)
- **Dockerized deployment** with Postgres-ready config

## Quick start (local)

```bash
python3 -m venv venv
source venv/bin/activate         # Windows: venv\Scripts\activate
pip install -r requirements.txt

export FLASK_SECRET_KEY="change-me-to-a-long-random-string"
export JWT_SECRET_KEY="change-me-too-a-different-long-random-string"

python3 run.py
```

Open **http://localhost:5000** for the dashboard. On first run a default
admin account is seeded:

- username: `admin` (override with `SEED_ADMIN_USERNAME`)
- password: `ChangeMe!2026` (override with `SEED_ADMIN_PASSWORD` — **do this**
  for anything beyond a local demo)

## Quick start (Docker)

```bash
docker compose up --build
```

Then visit http://localhost:5000. Set `FLASK_SECRET_KEY`, `JWT_SECRET_KEY`,
and `SEED_ADMIN_PASSWORD` via a `.env` file or exported env vars before
running in anything other than a throwaway demo.

## Deploying to Render

Connect this repository in Render and it will automatically detect the
root-level `render.yaml` Blueprint. Set `FLASK_SECRET_KEY`, `JWT_SECRET_KEY`,
`DATABASE_URL`, and `SEED_ADMIN_PASSWORD` when prompted, then deploy the
service.

## Running tests

```bash
python3 -m pytest tests/ -v
```

19 tests cover: registration + password policy, login + exponential-backoff
lockout behaviour, full TOTP MFA enrolment/login/recovery-code flow, admin
dashboard access control, and password-reuse blocking.

## API reference

| Method | Path                          | Auth        | Purpose                                  |
|--------|-------------------------------|-------------|-------------------------------------------|
| POST   | `/api/auth/register`          | none        | Create account (policy-enforced password) |
| POST   | `/api/auth/login`             | none        | Stage 1: password check                   |
| POST   | `/api/auth/verify-mfa`        | pre_mfa JWT | Stage 2: TOTP or recovery code             |
| POST   | `/api/auth/mfa/setup`         | access JWT  | Begin MFA enrolment, returns QR URI        |
| POST   | `/api/auth/mfa/confirm`       | access JWT  | Confirm enrolment, returns recovery codes  |
| POST   | `/api/auth/refresh`           | refresh JWT | Exchange for a new access token            |
| POST   | `/api/auth/logout`            | access JWT  | Client-side token discard                  |
| POST   | `/api/auth/change-password`   | access JWT  | Change password (reuse-checked)            |
| GET    | `/api/auth/me`                | access JWT  | Current session info                       |
| GET    | `/api/admin/stats`            | admin JWT   | Dashboard summary counters                 |
| GET    | `/api/admin/audit-log`        | admin JWT   | Paginated audit trail                      |
| GET    | `/api/admin/login-attempts`   | admin JWT   | Raw login attempt log                      |
| GET    | `/api/admin/lockouts`         | admin JWT   | Active + historical lockouts               |
| POST   | `/api/admin/unlock/<user_id>` | admin JWT   | Manually clear an active lockout           |

Send the JWT as `Authorization: Bearer <token>`.

## Project structure

```
mlpsaps/
├── app/
│   ├── __init__.py          # app factory, DB init, admin seeding
│   ├── extensions.py        # db, limiter instances
│   ├── models.py            # User, LoginAttempt, Lockout, AuditLog, ...
│   ├── security/
│   │   ├── hashing.py           # bcrypt hash/verify
│   │   ├── password_validator.py# policy + breach-list check
│   │   ├── brute_force.py       # adaptive lockout logic
│   │   ├── totp_utils.py        # TOTP + recovery codes
│   │   ├── jwt_utils.py         # token issuance/decoding
│   │   ├── decorators.py        # @token_required, @admin_required
│   │   └── audit_logger.py      # append-only event log
│   ├── routes/
│   │   ├── auth.py          # register/login/mfa/session endpoints
│   │   └── admin.py         # dashboard/admin endpoints
│   └── templates/index.html # single-page dashboard UI
├── tests/                   # pytest suite (19 tests)
├── config.py
├── run.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── SECURITY.md              # design rationale for every control
```

## Team task split (suggested)

- **Core security engine** — hashing, lockout/backoff, brute-force detection
  (`app/security/hashing.py`, `brute_force.py`, `config.py`)
- **Auth layers + database** — models, schema, TOTP integration
  (`app/models.py`, `app/security/totp_utils.py`, `app/routes/auth.py`)
- **Frontend, dashboard, docs** — dashboard UI, README/SECURITY write-up, demo prep
  (`app/templates/index.html`, `app/routes/admin.py`, docs)
