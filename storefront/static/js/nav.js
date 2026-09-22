/*
 * Reflects login state in the header nav. This is a display convenience
 * only -- it trusts the locally cached user for the greeting text, but any
 * page that actually gates content (account.html) re-verifies the token
 * against MLPSAPS's /api/auth/me before showing anything (see auth-guard.js).
 */

function renderNavAuth() {
  const area = document.getElementById("nav-auth-area");
  if (!area) return;

  if (MLPSAPS.isLoggedIn()) {
    const user = MLPSAPS.getCachedUser();
    const name = user ? user.username : "account";
    area.innerHTML = `
      <a href="/account" class="greet">Hi, ${escapeHtml(name)}</a>
      <button type="button" class="link-btn" id="nav-logout-btn">Log out</button>
    `;
    document.getElementById("nav-logout-btn").addEventListener("click", async () => {
      await MLPSAPS.logout();
      window.location.href = "/";
    });
  } else {
    area.innerHTML = `<a href="/login" id="nav-login">Log in</a>`;
  }
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

document.addEventListener("DOMContentLoaded", renderNavAuth);
