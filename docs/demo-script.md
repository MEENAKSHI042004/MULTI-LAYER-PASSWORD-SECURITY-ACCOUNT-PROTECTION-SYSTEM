# MLPSAPS — Live Demo Script

A linear walkthrough for the review. Anyone on the team can read this and
present it, even without knowing every module in depth.

## Pre-flight checklist (do this 10 minutes before, not live)

- [ ] **Use `localhost`, never `127.0.0.1`.** Open the dashboard at
  `http://localhost:5000` and the storefront at `http://localhost:5001`. A
  security key enrolled on `127.0.0.1` fails (WebAuthn's RP ID is `localhost`).
- [ ] **Start both servers** (two terminals): `python run.py` (or
  `docker compose up`) and, from `storefront/`, `python app.py`.
- [ ] Set `SEED_ADMIN_PASSWORD` before the first start so you know the admin
  password; log in as `admin` once to confirm.
- [ ] **Real hardware ready:** Windows Hello / Touch ID set up in the OS (or a
  USB key plugged in); use Chrome or Edge (Safari for Touch ID).
- [ ] **Pre-create the demo user and pre-enrol their security key** (dashboard
  -> MFA setup -> Add Security Key), so the live step only has to *sign in*.
- [ ] Open **two separate browser windows side by side** -- dashboard in one,
  storefront in the other -- not two tabs. The storefront deliberately pauses
  its session check while its tab is hidden, so a background tab won't lock out
  until you switch back to it.
- [ ] Record a 60-90 second screen capture of steps 10a-10d working, as a
  fallback if live networking or hardware misbehaves.

---

### 1. Register a new user
**Say:** "Let's start by creating an account. Passwords are checked
client-side for quick feedback, and enforced server-side so nothing weak
ever gets hashed and stored."
**Do:** Go to Register, type a weak password first to show the live
strength meter and rejection message, then a strong one to succeed.
**Fallback:** if registration errors, show the `password_validator.py`
code instead and explain the rules there.

### 2. Show the password entropy meter
**Say:** "This meter estimates entropy in bits based on which character
classes are used, giving the user real-time feedback beyond just pass/fail."
**Do:** Type progressively more complex passwords and point out the label
changing (Weak → Fair → Strong → Very Strong).

### 3. Trigger and demonstrate a lockout
**Say:** "Now let's see the brute-force protection. Repeated wrong
passwords lock the account, and the lockout duration doubles each time —
30 seconds, 60, 120, up to a 1-hour cap."
**Do:** Fail login 5 times on purpose in the incognito window; the 6th
attempt returns "Account temporarily locked" with the retry countdown.
**Fallback:** if it doesn't trigger live, run `python cli_demo.py
simulate-lockout --username <name>` in a terminal instead — it shows the
same escalating backoff cleanly from the command line.

### 4. Manually unlock from the admin dashboard
**Say:** "Rather than waiting out the lockout, an admin can clear it
directly."
**Do:** In the main (admin) window, open Security dashboard, find the
locked account in the Lockouts table, click Unlock, show the success
message and the row updating.

### 5. Enroll in MFA
**Say:** "Users can add a second factor — TOTP, the same standard used by
Google Authenticator and Authy."
**Do:** Log in as the test user, go to MFA setup, generate the QR code,
scan it (or just show the manual secret key), enter the 6-digit code,
show the recovery codes being issued.

### 6. Log in with MFA required
**Say:** "Now login is staged — password first, then the authenticator
code."
**Do:** Log out, log back in as that user, show the password step
succeeding but only issuing a limited pre-MFA token, then completing with
the TOTP code to get a full session.

### 7. Update profile details
**Say:** "Users can also manage their own account information."
**Do:** Go to Account, update the display name and email, show the
success message and the change persisting after a refresh.

### 8. Show the audit log and export it
**Say:** "Every security-relevant action — registrations, logins,
lockouts, MFA events — is written to an append-only audit log."
**Do:** In the admin dashboard, scroll through the Audit log table
showing entries from everything just demonstrated, then click Export CSV
and open the downloaded file.

### 9. Run the CLI demo tool
**Say:** "Everything we just did through the browser is also directly
testable from the terminal, without any UI at all — useful for quick
verification or scripting."
**Do:** Run `python cli_demo.py register`, then `python cli_demo.py
simulate-lockout`, narrating the escalating lockout output.

### 10. Show the demo storefront as a second client
**Say:** "Everything so far has been MLPSAPS's own dashboard. To prove this
works as a real authentication provider -- not just for itself -- we built a
separate storefront with no login logic of its own. Every account action goes
to MLPSAPS's API."

**10a. Password login on the second site.**
**Do:** In the storefront window, log in with the demo user's username and
password. Show it land on the Account page, which is fetched live from
`/api/auth/me`.
**Say:** "Different site, different port, different origin -- and it only
works because MLPSAPS explicitly allows that one origin; it is not open to the
world."

**10b. Passwordless login on the second site.**
**Do:** Log out of the storefront. Type the username, click **Sign in with
security key / Touch ID**, and touch the key / use the fingerprint.
**Say:** "Same MLPSAPS backend, but no password at all -- the private key
never leaves the device."
**Fallback:** show the pre-recorded clip, or the browser network tab calling
`/api/auth/webauthn/login/begin` and `/complete`.

**10c. Revoke the session from MLPSAPS.**
**Do:** In the dashboard window go to **Account -> Active sessions**. You will
see two sessions: the dashboard's own (tagged "this session") and the
storefront's. Click **Revoke** on the one that is *not* tagged.
**Say:** "I'm signing the storefront out from MLPSAPS, a different site."

**10d. Watch the storefront lock itself out.**
**Do:** Keep the storefront window visible and don't touch it. Within about 15
seconds it redirects to the login page on its own.
**Say:** "No click, no reload -- the storefront re-checks the token with
MLPSAPS every 15 seconds, so a revoked session is cut off almost immediately.
One backend is the single source of truth."
**If it doesn't happen:** the storefront window was probably in a background
tab -- click on it. If it still doesn't, the pre-recorded clip is the fallback.

### 11. Close with the architecture diagram
**Say:** "To tie it together, here's how a request actually flows through
the system."
**Do:** Show `docs/architecture-diagram.svg` — walk through registration →
hashing → login → lockout check → policy check → MFA/WebAuthn → session
issuance, with the audit logger running alongside every stage, and point
out the demo storefront as a second client feeding into the same login
flow.

---

## If Something Breaks Mid-Demo

- **Server won't start:** check the terminal for a stack trace, most
  likely a missing `pip install` package or the venv not activated
  (`(venv)` should show in the prompt).
- **Login/lockout doesn't trigger as expected:** fall back to
  `cli_demo.py simulate-lockout`, which reproduces it reliably every time.
- **CSV export doesn't download:** open `docs/security-testing-report.md`
  instead and read the pytest results table as backup evidence.
- **Anything else fails live:** narrate what it's supposed to do and show
  the relevant code file instead of debugging live in front of reviewers.