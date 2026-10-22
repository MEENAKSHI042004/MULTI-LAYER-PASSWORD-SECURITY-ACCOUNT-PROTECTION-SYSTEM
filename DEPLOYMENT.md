# Deploying MLPSAPS + the demo storefront

## Local (recommended for the review demo)

```
docker compose up --build          # MLPSAPS + Postgres on :5000
cd storefront && pip install -r requirements.txt && python app.py   # :5001
```

Open **http://localhost:5001** (not 127.0.0.1 -- WebAuthn's RP ID is `localhost`).
Set `FLASK_SECRET_KEY`, `JWT_SECRET_KEY` and `SEED_ADMIN_PASSWORD` in a `.env`
first (see `.env.example`); the compose defaults are placeholders.

## Render (public URL)

`render.yaml` defines the database and both services. In the Render dashboard:
**New -> Blueprint -> pick this repo**. Render then:

- generates `FLASK_SECRET_KEY` and `JWT_SECRET_KEY` itself,
- wires `DATABASE_URL` from the managed Postgres,
- prompts you for `SEED_ADMIN_PASSWORD` (choose a strong one and keep it).

The URL-dependent values can only be filled in after the first deploy, because
the URLs don't exist until then. Once both services show a URL:

| Service | Variable | Value |
|---|---|---|
| mlpsaps | `CORS_ALLOWED_ORIGINS` | the storefront's `https://...` URL |
| mlpsaps | `WEBAUTHN_RP_ID` | the mlpsaps host only, e.g. `mlpsaps.onrender.com` |
| mlpsaps | `WEBAUTHN_ORIGIN` | the mlpsaps `https://...` URL |
| mlpsaps-storefront | `MLPSAPS_API_BASE` | the mlpsaps `https://...` URL |

Save, let both services redeploy, then test register -> login -> account.

### Check after the first deploy

1. **Proxy hops.** `TRUST_PROXY_HOPS=1` assumes one proxy in front. Log in once,
   then look at the audit log in the dashboard: the IP should be yours. If it's
   a Render-internal address, the real chain is longer -- raise the value by one
   and re-check. Never set it higher than the true number of proxies; extra hops
   let a client forge its own IP.
2. **Admin password.** Log in as the seeded admin with the password you chose and
   change it.

### Known limits of a Render deploy

- **Passwordless across both sites does not work on default `onrender.com`
  domains.** A WebAuthn RP ID must be the page's host or a registrable parent of
  it; `onrender.com` is a public suffix, so the two services share no valid RP
  ID. With the settings above, WebAuthn works on the MLPSAPS dashboard only.
  Password login across both sites works normally. For cross-site passwordless
  you need a custom domain with subdomains (e.g. `auth.example.com` and
  `shop.example.com`, `WEBAUTHN_RP_ID=example.com`, both origins in
  `WEBAUTHN_ORIGIN`, both in `CORS_ALLOWED_ORIGINS` as needed).
- **Rate-limit counters are per worker** (`memory://` storage, 2 Gunicorn
  workers), so effective limits are looser than configured. Account lockout is
  unaffected (it's stored in the database). A Redis `RATELIMIT_STORAGE_URI`
  fixes this.
- **Free Postgres expires** after a limited period; don't keep anything on it
  that you need long-term.
- **Free web services sleep** when idle; the first request after a pause is slow.
