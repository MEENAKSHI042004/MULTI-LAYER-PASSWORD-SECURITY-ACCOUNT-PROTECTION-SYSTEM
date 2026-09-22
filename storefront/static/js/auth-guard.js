/*
 * Gate for pages that require a logged-in MLPSAPS user. Redirects to /login
 * immediately if there's no token at all, and otherwise calls the REAL
 * /api/auth/me endpoint to prove the token is actually valid (not expired,
 * not revoked) before revealing any page content. Returns the verified user
 * object on success so the caller can render it.
 *
 * Also starts a periodic background re-check (see startSessionWatch below)
 * so a session revoked in the MLPSAPS admin dashboard locks the user out of
 * this page immediately, instead of only on the next page load/action.
 */

const SESSION_CHECK_INTERVAL_MS = 15000; // how often to re-verify the token while the page is open
let sessionWatchTimer = null;

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

  startSessionWatch();
  return result.data.user;
}

/*
 * Runs in the background for as long as this page stays open. Every
 * SESSION_CHECK_INTERVAL_MS, silently re-checks the token against the real
 * MLPSAPS /api/auth/me endpoint. If the session was revoked in the admin
 * dashboard in the meantime, this catches it and kicks the user out right
 * away -- no page reload or click required.
 */
function startSessionWatch() {
  if (sessionWatchTimer) return; // already running, don't start a second timer

  sessionWatchTimer = setInterval(async () => {
    // If the tab isn't visible, skip this round -- no point spamming the API
    // for a page the user isn't even looking at right now.
    if (document.hidden) return;

    const result = await MLPSAPS.me();
    if (!result.ok) {
      stopSessionWatch();
      MLPSAPS.clearSession();
      goToLogin();
    }
  }, SESSION_CHECK_INTERVAL_MS);
}

function stopSessionWatch() {
  if (sessionWatchTimer) {
    clearInterval(sessionWatchTimer);
    sessionWatchTimer = null;
  }
}

function goToLogin() {
  stopSessionWatch();
  const next = encodeURIComponent(window.location.pathname);
  window.location.href = `/login?next=${next}`;
}