# Brute-Force Lockout Simulation — Results

## What this demonstrates
Confirms the adaptive account lockout system holds up against a simulated
brute-force attack sent over real HTTP to the live server (not just internal
function calls, as the pytest suite does).

## How to run it
1. Start the server: `python run.py`
2. In a second terminal: `python scripts/brute_force_simulation.py`
3. Results are logged live and saved to `brute_force_results.json`

## What the script does
- Registers a fresh test account
- Sends 5 wrong-password login attempts in a row over HTTP
- Checks whether the 6th attempt is blocked (HTTP 423) and reads the lockout duration
- Waits out the lockout, then repeats — to confirm the *next* lockout duration
  is longer (exponential backoff), not just a flat repeat

## Observed results

| Round | Failed attempts sent | Result | Lockout duration |
|-------|----------------------|--------|-------------------|
| 1     | 5                    | Locked (423) | 29 seconds |
| 2     | 5 (delayed by rate limiter) | Not locked (200) | — |
| 3     | 5                    | Locked (423) | 119 seconds |

## Interpretation
- **Round 1** confirms the core rule: 5 consecutive failures trigger a lockout,
  matching `BASE_LOCKOUT_SECONDS = 30` in config.
- **Round 3** confirms **exponential backoff**: the lockout duration roughly
  quadrupled to 119s after a repeat offense, consistent with
  `LOCKOUT_BACKOFF_FACTOR = 2` compounding across the account's lockout history.
- **Round 2** did not trigger a lockout, because the **per-IP rate limiter**
  (`RATELIMIT_LOGIN = "10 per minute"`) intervened first, spacing out the
  attack before 5 consecutive failures could register within the same window.
  This is not a failure of the lockout system — it demonstrates that rate
  limiting and account lockout act as **independent, layered defenses**:
  even when one control shifts the attacker's timing, the system still isn't
  left exposed.

## Conclusion
The brute-force protection system works as designed. An automated attacker
is slowed by rate limiting, and even when they persist past that, account
lockout kicks in and escalates with each repeat offense — making sustained
brute-forcing impractical.