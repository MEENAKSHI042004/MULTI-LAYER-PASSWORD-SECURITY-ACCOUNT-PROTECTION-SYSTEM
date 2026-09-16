### Breach-password check (Have I Been Pwned)

**What changed:** Password validation previously rejected only a small
hardcoded list of the most obvious weak passwords (`"password"`,
`"123456"`, etc.). This has been replaced with a live check against the
[Have I Been Pwned](https://haveibeenpwned.com/) (HIBP) Pwned Passwords
database, which contains hundreds of millions of passwords known to have
appeared in real-world data breaches.

**How the check works (k-anonymity model):**
1. The submitted password is hashed locally using SHA-1.
2. Only the **first 5 characters** of that hash are sent to HIBP's API
   (`GET /range/{prefix}`).
3. HIBP returns every hash suffix in its database that shares that same
   5-character prefix — typically several hundred to a few thousand
   entries — each paired with how many times it has appeared in known
   breaches.
4. The full hash suffix is compared **locally** against that returned
   list to determine whether there's a match.

At no point does the full password, or even its full hash, leave the
server. HIBP only ever sees a 5-character prefix shared by thousands of
unrelated passwords, so it cannot feasibly determine which exact password
was checked.

**Fallback behavior:** If the HIBP API is unreachable (network failure,
timeout, or the service being down), the check fails safe by falling back
to the original small local list of common passwords rather than
silently allowing the registration/password-change through unchecked.
This trades some breach-detection coverage for availability, so a
registration can never be permanently blocked by a third-party outage.

**Testing:** Because the check depends on a live external API, the test
suite mocks `check_pwned()` via an `autouse` pytest fixture in
`conftest.py`, so all existing tests run deterministically offline without
depending on network access or on whether a given test password happens
to appear in a real breach dump. A dedicated test,
`test_registration_rejects_breached_password`, overrides the mock to
simulate a breached password and confirms the rejection path itself
works correctly.

**Manually verified:** Registering with the password `password123`
returns a `400` with the message *"This password has appeared in
2,266,543 known data breaches; choose a different one."* A strong,
randomly generated password registers successfully with no breach-related
error.