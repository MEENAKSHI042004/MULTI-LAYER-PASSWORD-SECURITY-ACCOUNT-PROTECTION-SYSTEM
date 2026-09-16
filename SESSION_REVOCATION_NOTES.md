\# Session Revocation — Notes



\## The problem

Logout only removed the access token from the client's device. The JWT

itself stayed technically valid server-side until it naturally expired,

since nothing tracked which tokens had been logged out.



\## What was already built

The revocation infrastructure existed before this task:

\- Every JWT carries a unique `jti` (JWT ID) claim, generated in `jwt\_utils.py`.

\- A `RevokedToken` table stores revoked jtis; `token\_required` checks every

&#x20; incoming request's jti against this table before trusting the token.

\- A `Session` table tracks one row per login (access token), with

&#x20; `/api/auth/sessions` (list) and `/api/auth/sessions/<id>/revoke` (end one)

&#x20; already implemented — active-session tracking was mostly done already.

\- `/logout` already revoked the \*access\* token's jti and marked its session

&#x20; row as revoked.



\## The gap this closes

Every login issues \*\*two\*\* tokens: an access token (short-lived, \~15 min)

and a refresh token (long-lived, 7 days). Logout and session-revoke only

ever handled the access token. The refresh token was never tracked or

revoked anywhere — so a user (or attacker with a copied token) could still

call `/api/auth/refresh` after "logging out" and mint a brand-new valid

access token, fully bypassing the logout.



\## The fix

\- Added a `refresh\_jti` column to the `Session` model, so each session row

&#x20; now remembers both of its tokens' ids.

\- `login()`, `verify\_mfa()`, and `refresh()` now pass the refresh token's

&#x20; jti into `\_create\_session()`.

\- `/logout` and `/sessions/<id>/revoke` now also add the session's

&#x20; `refresh\_jti` to `RevokedToken`, so both tokens die together.



\## Proof

Two new tests in `tests/test\_session\_revocation.py`:

\- `test\_logout\_revokes\_refresh\_token` — logs in, logs out, then confirms

&#x20; the refresh token can no longer be used to get a new access token (401).

\- `test\_revoking\_a\_session\_also\_revokes\_its\_refresh\_token` — confirms

&#x20; ending a session via `/sessions/<id>/revoke` also kills its refresh token.



All 21 tests pass (19 existing + 2 new).

