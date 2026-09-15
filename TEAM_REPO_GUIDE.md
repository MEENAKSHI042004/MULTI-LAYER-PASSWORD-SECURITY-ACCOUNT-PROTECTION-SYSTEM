# MLPSAPS — What's Done + How to Work With This Repo

Repo: https://github.com/MEENAKSHI042004/MULTI-LAYER-PASSWORD-SECURITY-ACCOUNT-PROTECTION-SYSTEM

---

## Part 1 — What's already done (in `main`)

### Credential storage
- [x] bcrypt password hashing with a unique random salt per user
- [x] Password policy enforcement: min length, upper/lower/digit/special char, common-breached-password rejection
- [x] Password history check (last 5) to block reuse on change

### Brute-force protection
- [x] Every login attempt (success/fail) logged with username, IP, stage, reason
- [x] Adaptive account lockout: duration doubles on each repeat offense, capped at 1 hour
- [x] Lockouts auto-expire; admin API endpoint to clear one manually
- [x] Failed-attempt counter resets on a successful login
- [x] Per-IP rate limiting on `/register` and `/login`

### Multi-factor authentication
- [x] TOTP (RFC 6238) enrollment with QR-code provisioning URI
- [x] Staged login: password-correct issues a limited "pre-MFA" token, not a full session
- [x] One-time recovery codes, stored as bcrypt hashes, single-use
- [x] Wrong MFA codes count toward the same lockout system as wrong passwords

### Sessions
- [x] JWT access tokens (short-lived) + refresh tokens (long-lived)
- [x] `/api/auth/refresh` to get a new access token without re-logging in

### Audit logging & admin dashboard
- [x] Append-only event log (register, login success/fail, lockout, MFA, password change, admin actions)
- [x] Admin dashboard: audit log table, raw login-attempts table, lockout table, summary stats
- [x] Auto-seeded default admin account on first run

### Infrastructure
- [x] SQLAlchemy models, SQLite by default, PostgreSQL-ready via `DATABASE_URL`
- [x] Dockerfile + docker-compose for one-command local deployment
- [x] 19 passing pytest tests (registration, lockout/backoff math, full MFA flow, admin access control, password reuse)

### Documentation
- [x] `README.md` — setup, run, full API reference
- [x] `SECURITY.md` — design rationale for every security control (for the viva)
- [x] `PROJECT_STATUS_AND_REMAINING_TASKS.md` — what's left, split across the team

### Not done yet (see `PROJECT_STATUS_AND_REMAINING_TASKS.md` for the full breakdown)
Session revocation/active-session tracking, tamper-evident (hash-chained) audit log,
per-user rate limiting, real breach-password API integration, PostgreSQL tested
end-to-end, brute-force simulation script, CLI demo tool, password entropy
scoring, audit-log export, profile editing, cloud-deployment config, architecture
diagram, and the security-testing writeup.

---

## Part 2 — Instructions for handling this repo safely

Please read this before touching anything. The goal is that nobody's work
ever gets silently overwritten.

### 2.1 One-time setup

```bash
git clone https://github.com/MEENAKSHI042004/MULTI-LAYER-PASSWORD-SECURITY-ACCOUNT-PROTECTION-SYSTEM.git
cd MULTI-LAYER-PASSWORD-SECURITY-ACCOUNT-PROTECTION-SYSTEM

git config user.name "Your Full Name"
git config user.email "your.email@example.com"

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python3 -m pytest tests/ -v     # confirm all 19 tests pass before you change anything
```

If any test fails right after a fresh clone, stop and flag it in the group
chat before writing new code on top of it — don't assume it's your fault.

### 2.2 Never work directly on `main`

`main` should always be in a working state — Meenakshi (or whoever is
merging) is the only one who pushes to it directly. Everyone else works on
their own branch:

```bash
git checkout -b yourname/feature-you-are-building
# e.g. git checkout -b chinmayi/session-revocation
```

Do your work, commit as you go with clear messages:

```bash
git add -A
git commit -m "Add session revocation table and check on token decode"
```

### 2.3 Before you push — always pull `main` first

Someone else may have pushed changes while you were working. Never push
without doing this first:

```bash
git checkout main
git pull origin main
git checkout yourname/feature-you-are-building
git merge main
```

If Git reports a merge conflict, **do not guess and delete blocks blindly**.
Open the conflicted file, look for the `<<<<<<<` / `=======` / `>>>>>>>`
markers, and manually decide which lines to keep (usually both changes need
to be combined, not one replacing the other). If you're unsure, screenshot
it and ask in the group chat rather than force-resolving it.

### 2.4 Push your branch, not `main`

```bash
git push origin yourname/feature-you-are-building
```

Then open a Pull Request on GitHub into `main` so someone else can look it
over before it merges — even a 30-second glance catches a lot. Once it's
reviewed, merge it through GitHub's UI (or ask Meenakshi to).

### 2.5 Things that will break the project if you do them — please don't

- **Don't run `git push --force` on `main`, ever.** This rewrites history
  and can permanently delete other people's commits. If you think you need
  to force-push, stop and ask first.
- **Don't commit the `instance/` folder, `__pycache__/`, or `.pytest_cache/`.**
  These are already in `.gitignore` — if `git status` shows them as
  untracked, that's correct, leave them alone. If you ever see them staged
  (`git add -A` followed by `git status` showing them in green), un-stage
  them with `git reset instance/` before committing.
- **Don't commit real secrets.** `FLASK_SECRET_KEY`, `JWT_SECRET_KEY`, and
  `SEED_ADMIN_PASSWORD` should only ever be set as environment variables or
  in a local `.env` file (also gitignored) — never typed directly into
  `config.py` or any file that gets committed.
- **Don't edit someone else's module and push straight to `main` without
  telling them**, even if you're just "fixing a bug." A quick heads-up
  avoids two people fixing the same thing in conflicting ways.
- **Don't delete or rename existing files/functions other modules depend
  on** (e.g. renaming something in `app/security/hashing.py`) without
  checking who else imports it — grep for the name across the repo first:
  `grep -rn "function_name" .`
- **Always run the test suite before pushing.** If your change makes an
  existing test fail, fix it or ask before pushing — don't push broken
  tests and assume someone else will notice.

### 2.6 If something goes wrong

- **Accidentally committed something you shouldn't have (like a secret)?**
  Don't just delete it in a new commit — it's still in history. Stop and
  ask; there's a proper way to purge it from git history.
- **Made a mess on your own branch and want to start over?** It's your
  branch — safe to delete and recreate:
  ```bash
  git checkout main
  git branch -D yourname/feature-you-are-building
  git checkout -b yourname/feature-you-are-building
  ```
- **Not sure if a command is safe?** If it has `--force`, `-f`, `reset --hard`,
  or `push` in it and you're not 100% sure what it does, ask before running
  it. All of these can discard work with no undo.
