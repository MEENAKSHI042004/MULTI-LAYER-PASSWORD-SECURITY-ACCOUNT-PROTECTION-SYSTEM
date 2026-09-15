# Multi-Layer Password Security & Account Protection System
### Project Status & Remaining Work — Phase 2

---

## 1. Where the project stands

The Phase 2 system is built and running end-to-end as a Flask REST API with a
connected web dashboard, backed by a SQLite database (swappable for
PostgreSQL through a single config value). It has been tested with an
automated suite of 19 passing tests covering every major flow, and manually
verified by running the server and walking through registration, login,
MFA enrollment, and the admin dashboard live.

### Account creation and credential storage

Users register with a username, email, and password. Every password is
checked against a policy before it's accepted — minimum length, a mix of
uppercase, lowercase, digits and symbols, and a check against a list of
commonly breached passwords — and rejected with a clear reason if it doesn't
qualify. Accepted passwords are never stored as-is: they're hashed with
bcrypt, which generates a unique random salt for every password so that even
two users with the same password end up with completely different stored
values. When a user later changes their password, the system also checks it
against their last five passwords so they can't just cycle back to an old
one.

### Login and brute-force protection

Login happens in stages. The first stage checks the password against the
stored hash. Every attempt — successful or not — is logged with the
username, IP address, and outcome. If someone fails to log in repeatedly,
the account is automatically locked for a period of time that grows each
time it happens (starting short and doubling on repeated violations, up to
a one-hour cap), so a real user who mistypes their password a couple of
times is barely inconvenienced, while sustained automated guessing becomes
increasingly expensive. Lockouts clear themselves automatically once the
timer runs out, and there's also an admin endpoint to clear one manually.
On top of this, the login and registration endpoints are throttled per IP
address, so a flood of requests from one source gets slowed down even
before any single account is locked.

### Multi-factor authentication

Once a user's password is correct, if they've enabled two-factor
authentication the system doesn't hand them a session yet — it issues a
short-lived, limited-purpose token that only allows access to the MFA
verification step, nothing else. The user then enters a 6-digit code from
an authenticator app, generated using the time-based one-time password
standard. Enrollment is done by scanning a QR code shown in the dashboard.
At enrollment, the user is also given a set of one-time recovery codes to
use if they lose access to their authenticator app; these are stored as
bcrypt hashes rather than plain text, and each one can only be used once.
Wrong MFA codes count toward the same lockout system as wrong passwords, so
that stage can't be brute-forced either.

### Sessions

After a successful login (with or without MFA), the system issues a pair of
signed tokens: a short-lived one used for normal requests, and a longer-lived
one used only to request a fresh short-lived token without logging in again.
These tokens are self-contained and digitally signed, so the server doesn't
need to keep track of active sessions in a database to check whether they're
valid.

### Audit logging and the admin dashboard

Every meaningful security event — registrations, successful and failed
logins, lockouts, MFA setup, password changes, admin actions — is written to
a log that is only ever added to, never edited. Admin users can log into a
dashboard that shows this log alongside a live table of raw login attempts,
a table of lockout history, and summary counters (total users, total
attempts, failed attempts, currently locked accounts). A working admin
account is created automatically the first time the app runs.

### Deployment and testing

The whole application is packaged to run with a single Docker command, with
the database and secret keys configurable through environment variables so
it isn't hardwired to development settings. An automated test suite
exercises registration and password rules, the full login and lockout
behaviour (including checking that the lockout timer actually grows on
repeat offenses), the complete MFA setup-login-recovery flow, and the admin
dashboard's access restrictions — all 19 tests currently pass.

### Documentation

A design-decisions document explains the reasoning behind every security
choice made (why bcrypt, why the lockout grows the way it does, why MFA
uses a separate limited token, and so on), written so it can be defended
directly to the project guide and reviewer. A setup guide and API reference
covering every endpoint is also in place.

---

## 2. What's genuinely left before the final review

The core system works, but going back through the original abstract and
slide deck carefully, a number of specific items named there aren't built
yet. These are listed below by area, split across the two of you — the
proposed split follows the same shape as before, but is more complete than
the earlier draft of this document.

### For Chinmayi

- **Session revocation.** Logging out currently only removes the token on
  the user's own device — the token itself stays technically valid until
  it naturally expires a few minutes later, since nothing on the server
  tracks which tokens have already been logged out. This needs a small
  store that records revoked token IDs, checked on every request.
- **Active-session tracking.** The plan calls for users (and admins) to be
  able to see and end other active sessions on an account — e.g. "signed in
  on 2 devices, end the other one." Right now there's no concept of a
  session beyond the token itself, so this needs an actual sessions table
  tied to the revocation work above.
- **Tamper-evident audit logging.** The log is currently append-only in the
  sense that nothing in the app edits old rows, but that's not the same as
  tamper-evident — someone with direct database access could still alter a
  row without it being detectable. Making it genuinely tamper-evident means
  chaining each entry to a hash of the one before it, so any edit breaks
  the chain and can be caught by verification.
- **Per-user rate limiting.** The current throttling is per IP address only.
  The plan calls for limiting requests per account as well, so that an
  attacker spreading login attempts for one account across many IP
  addresses is still slowed down even though no single IP looks abusive.
- **Upgrading the breach-password check.** The password validator currently
  rejects a short hardcoded list of the most obvious weak passwords. This
  should be swapped for a real check against the "Have I Been Pwned" breach
  database, using their privacy-safe lookup method so full passwords are
  never sent anywhere over the network.
- **Making the PostgreSQL path actually work end-to-end.** The config
  supports swapping SQLite for PostgreSQL and the Docker setup has a
  disabled Postgres service, but it hasn't actually been connected and
  tested against a running Postgres instance.
- **A brute-force simulation script.** The project plan calls for an actual
  demonstration that the lockout system holds up under a simulated attack —
  a script that hammers the login endpoint repeatedly and confirms the
  account locks and the delay grows as expected, with results captured for
  the review.

### For Thrisha

- **A manual-unlock button in the dashboard.** The backend already has an
  endpoint to clear a lockout early, but there's no button for it in the
  dashboard UI yet — an admin has to call the endpoint directly.
- **Profile management.** Users can currently change their password but
  can't edit anything else about their account (email, display info) from
  the dashboard — a simple form and endpoint for that is still open.
- **Password entropy display.** The validator currently checks for a mix of
  character types but doesn't calculate or show an actual entropy score,
  which the project plan names specifically as part of the password-policy
  engine — this could be added as a live strength meter on the registration
  form.
- **Audit-log report export.** The dashboard shows the audit log on screen,
  but there's no way to export it as a CSV or PDF report, which the plan
  calls for as part of the audit-logging module.
- **A CLI demonstration tool.** The original Phase 1 plan calls for a
  command-line demo of the core flows, separate from the web dashboard —
  a small script that can register a user, log in, and show a lockout
  happening, purely from the terminal.
- **Cloud-deployment configuration.** The app is containerized for local
  Docker use; a configuration for actually deploying it to a cloud
  provider (even a simple one, like a Render/Railway config file or a
  basic Nginx reverse-proxy setup) is still needed.
- **An architecture diagram.** A visual showing how a request moves through
  the system — registration → hashing, login → lockout check → MFA →
  session tokens, audit logging running alongside all of it — for the
  review slides.
- **A one-page "what changed since Phase 1" summary.** Something reviewers
  can glance at that shows the delta between the original presentation-only
  phase and the working system that now exists.
- **A short security-testing writeup.** Once Chinmayi's brute-force
  simulation script produces results, turning those results (plus the
  existing 19 automated tests) into a short readable report for the
  submission — what was tested, what passed, and what it demonstrates.
- **Demo script for the review.** A written walk-through of what to show
  live during the presentation, so it goes smoothly regardless of who's
  presenting.
