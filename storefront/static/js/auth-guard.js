/*
 * Gate for pages that require a logged-in MLPSAPS user. Redirects to /login
 * immediately if there's no token at all, and otherwise calls the REAL
 * /api/auth/me endpoint to prove the token is actually valid (not expired,
 * not revoked) before revealing any page content. Returns the verified user
 * object on success so the caller can render it.
 */
async function requireAuth() {
  if (!MLPSAPS.isLoggedIn()) {
    goToLogin();
    return null;
  }

  const result = await MLPSAPS.me();
  if (!result.ok) {
    // Token missing/expired/revoked -- MLPSAPS said no, so we don't trust it.
    MLPSAPS.clearSession();
    goToLogin();
    return null;
  }
  return result.data.user;
}

function goToLogin() {
  const next = encodeURIComponent(window.location.pathname);
  window.location.href = `/login?next=${next}`;
}
