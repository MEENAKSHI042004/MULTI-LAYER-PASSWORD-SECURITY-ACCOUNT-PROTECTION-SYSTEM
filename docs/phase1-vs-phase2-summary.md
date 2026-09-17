# MLPSAPS — What Changed Since Phase 1

| Area | Phase 1 (Planned / Presented) | Phase 2 (Now Working) |
|---|---|---|
| Password storage | Concept: bcrypt hashing described | Live: bcrypt + unique random salt per user, enforced server-side on every register/change |
| Password policy | Concept: strength rules discussed | Live: min length, upper/lower/digit/symbol, breach-list rejection, password-history check (last 5) |
| Brute-force protection | Concept: lockout idea presented | Live: adaptive lockout (duration doubles per repeat offense, capped at 1 hr), auto-expiry, admin manual-unlock endpoint + dashboard button, per-IP rate limiting |
| MFA | Not implemented | Live: TOTP (RFC 6238) enrollment with QR code, staged login (pre-MFA token → full session), one-time bcrypt-hashed recovery codes |
| Sessions | Not implemented | Live: JWT access + refresh tokens, `/api/auth/refresh` endpoint |
| Audit logging | Concept: logging idea mentioned | Live: append-only audit log for every security event, full admin dashboard (stats, audit table, login attempts, lockouts), CSV export |
| Admin tools | Not implemented | Live: admin dashboard, seeded default admin account, manual lockout-clear button |
| Infrastructure | Not implemented | Live: SQLAlchemy models, SQLite/PostgreSQL-ready, Dockerfile + docker-compose, cloud-deployment config |
| Testing | Not implemented | Live: 19+ passing pytest tests covering registration, lockout math, MFA flow, admin access, password reuse |
| Documentation | Slide deck only | Live: README (setup + API reference), SECURITY.md (design rationale), architecture diagram, this summary |

**In short:** Phase 1 presented the security concepts on slides. Phase 2 is a fully working Flask application implementing every one of those concepts end-to-end, plus MFA, sessions, an admin dashboard, and automated tests — none of which existed as running code before.
