# MLPSAPS — Live Demo Script

A linear walkthrough for the review. Anyone on the team can read this and
present it, even without knowing every module in depth.

**Before you start:** run `python run.py`, open `http://127.0.0.1:5000`,
and have a second incognito browser window ready for the "regular user"
side while you stay logged in as admin in the main window.

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
**Do:** Fail login 5 times on purpose in the incognito window, show the
"Account temporarily locked" message with the retry countdown.
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

### 10. Close with the architecture diagram
**Say:** "To tie it together, here's how a request actually flows through
the system."
**Do:** Show `docs/architecture-diagram.svg` — walk through registration →
hashing → login → lockout check → policy check → MFA → session issuance,
with the audit logger running alongside every stage.

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
