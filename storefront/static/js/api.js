/*
 * Thin wrapper around MLPSAPS's real REST API. Nothing here re-implements
 * auth logic -- it just calls the live endpoints at window.MLPSAPS_API_BASE
 * and manages the JWT the API returns.
 *
 * The token is kept in sessionStorage (cleared when the tab closes), never
 * in localStorage or a cookie, which keeps it out of reach of any longer-
 * lived cross-tab/cross-site storage and matches how MLPSAPS expects it:
 * as a Bearer token on the Authorization header, not a cookie.
 */

const MLPSAPS = {
  base: window.MLPSAPS_API_BASE,

  TOKEN_KEY: "mlpsaps_access_token",
  USER_KEY: "mlpsaps_user",

  getToken() {
    return sessionStorage.getItem(this.TOKEN_KEY);
  },

  setSession(accessToken, user) {
    sessionStorage.setItem(this.TOKEN_KEY, accessToken);
    if (user) sessionStorage.setItem(this.USER_KEY, JSON.stringify(user));
  },

  getCachedUser() {
    const raw = sessionStorage.getItem(this.USER_KEY);
    return raw ? JSON.parse(raw) : null;
  },

  clearSession() {
    sessionStorage.removeItem(this.TOKEN_KEY);
    sessionStorage.removeItem(this.USER_KEY);
  },

  isLoggedIn() {
    return !!this.getToken();
  },

  /** Low-level call to MLPSAPS. Adds the Authorization header automatically
   *  when a token is present and `auth` isn't explicitly disabled. */
  async call(path, { method = "GET", body, auth = true } = {}) {
    const headers = { "Content-Type": "application/json" };
    if (auth && this.getToken()) {
      headers["Authorization"] = `Bearer ${this.getToken()}`;
    }
    let res;
    try {
      res = await fetch(`${this.base}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      // Network failure / MLPSAPS not running / blocked by CORS.
      return { ok: false, status: 0, data: null, networkError: true };
    }
    let data = null;
    try {
      data = await res.json();
    } catch (e) {
      /* no JSON body */
    }
    return { ok: res.ok, status: res.status, data };
  },

  /** A message a person can act on, for any failed call() result. */
  errorMessage(result, fallback) {
    if (result.networkError) {
      return `Can't reach MLPSAPS at ${this.base}. Is it running?`;
    }
    if (result.status === 429) {
      return (result.data && result.data.error) || "Too many attempts. Please wait a minute and try again.";
    }
    if (result.status >= 500) {
      return "MLPSAPS had a server error. Please try again; if it keeps happening, check the MLPSAPS window.";
    }
    const d = result.data || {};
    const detail = Array.isArray(d.details) && d.details.length ? " " + d.details.join(" ") : "";
    return (d.error || fallback) + detail;
  },

  /** True only when MLPSAPS itself says the token is no good (not on network
   *  blips, rate limits or server errors, which must not log anyone out). */
  tokenRejected(result) {
    return !result.ok && (result.status === 401 || result.status === 403 || result.status === 422);
  },

  async register(username, email, password) {
    return this.call("/api/auth/register", {
      method: "POST",
      body: { username, email, password },
      auth: false,
    });
  },

  async login(username, password) {
    const result = await this.call("/api/auth/login", {
      method: "POST",
      body: { username, password },
      auth: false,
    });
    if (result.ok && result.data && result.data.access_token) {
      this.setSession(result.data.access_token, result.data.user);
    }
    return result;
  },

  /** Calls the real /api/auth/me endpoint -- this is what actually proves
   *  the stored token is valid, rather than just trusting local state. */
  async me() {
    const result = await this.call("/api/auth/me", { method: "GET" });
    if (result.ok && result.data && result.data.user) {
      sessionStorage.setItem(this.USER_KEY, JSON.stringify(result.data.user));
    }
    return result;
  },

  async logout() {
    if (this.getToken()) {
      await this.call("/api/auth/logout", { method: "POST" });
    }
    this.clearSession();
  },
};
