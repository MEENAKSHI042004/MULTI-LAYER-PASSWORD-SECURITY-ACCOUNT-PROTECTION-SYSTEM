# Basecamp Supply Co. (demo storefront)

A small, separate Flask app that demonstrates MLPSAPS acting as a shared
login provider for a second, independent site. It has **no auth logic of
its own** -- Register, Login, Account and Checkout all call MLPSAPS's real
`/api/auth/*` endpoints directly from the browser.

## Run it

1. Start MLPSAPS as usual (port 5000):
   ```
   python run.py
   ```
2. In a second terminal, from this folder:
   ```
   pip install -r requirements.txt
   python app.py
   ```
   The storefront runs on **port 5001**.

By default the storefront points at `http://127.0.0.1:5000`. Override with
the `MLPSAPS_API_BASE` env var if MLPSAPS runs elsewhere.

## How the auth flow works

- `static/js/api.js` -- thin wrapper around MLPSAPS's REST API. Stores the
  JWT access token in `sessionStorage` (not `localStorage`, not a cookie)
  and attaches it as a `Bearer` token on subsequent calls.
- `templates/register.html` / `templates/login.html` -- call
  `/api/auth/register` and `/api/auth/login` directly.
- `static/js/auth-guard.js` -- used by `account.html` and `checkout.html`.
  Redirects to `/login` if there's no token, and otherwise calls the real
  `/api/auth/me` to prove the token is still valid before showing any page
  content.
- `static/js/cart.js` -- fully client-side cart (`sessionStorage`), no
  backend involved.

## Why CORS matters here

Since the storefront (port 5001) and MLPSAPS (port 5000) are different
origins, the browser blocks the storefront's `fetch()` calls unless MLPSAPS
opts in via CORS. MLPSAPS's `CORS_ALLOWED_ORIGINS` config (see `config.py`
in the repo root) allowlists this storefront's origin specifically -- it is
**not** wildcarded, since an auth API with open CORS would let any site on
the internet read a logged-in user's session data.
