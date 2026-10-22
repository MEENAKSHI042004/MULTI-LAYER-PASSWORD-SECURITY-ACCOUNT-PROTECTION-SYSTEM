# Demo notes: session, audit and rate-limit features

## Before starting (3 terminals)
1. Terminal 1, project root: `python run.py` (MLPSAPS, port 5000)
2. Terminal 2, `storefront` folder: `python app.py` (shop, port 5001)
3. Terminal 3: free, for commands
Open the shop at http://localhost:5001 (use localhost, not 127.0.0.1).

## 1. Shared login (shop uses MLPSAPS)
- Register and log in on the shop, then open Account and Checkout.
- Point out: the shop has no login code of its own; every call goes to MLPSAPS.

## 2. Audit log is recorded
- Log in as the default admin (see the project README) and read the audit log.
- Show the register and login_success events for the shop user.

## 3. Tamper-evident audit log
- Show docs/audit_log_tamper_benchmark.md: a naive log misses an edited row,
  the hash chain flags the exact entry, and verification takes about 34 ms
  for 10,000 entries.

## 4. Session revocation and kick-out
- Keep the shop open on the Account page.
- List the user's sessions, then revoke the shop's session.
- The shop sends the user to the login page within about 15 seconds,
  with no reload.

## 5. Lockout and rate limiting
- Register a throwaway user (limit: 3 registrations per minute).
- Enter 5 wrong passwords; the next attempt returns "Account temporarily locked".
- Per-username limit: more than 10 attempts a minute on one username gives a 429
  (RATELIMIT_LOGIN_PER_USERNAME is 10 per minute). Lockout fires first, after 5 wrong
  passwords, so the lockout message appears well before any 429.

## 6. Hashing benchmark
- Show docs/bcrypt_vs_argon2id_benchmark.md (measured on this machine:
  Argon2id about 393 ms per hash, bcrypt about 787 ms).

## 7. IP spoofing fix
- Send a failed login with a forged X-Forwarded-For: 6.6.6.6 header.
- The audit log stores the real IP (127.0.0.1), not the forged one.