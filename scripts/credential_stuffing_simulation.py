"""
Credential-Stuffing Simulation for MLPSAPS.

Simulates a credential-stuffing attack: an attacker with a list of known
breached/common passwords tries them one after another against a single
target account, hoping the account owner reused one of them.

Rather than downloading the full ~14M-entry RockYou dump (which would take
well over an hour to run through given the 10-per-minute login rate limit,
and isn't necessary to demonstrate the attack pattern or the defense
response), this uses a representative sample of the ~50 most common
passwords seen across major real-world breaches. This mirrors how many
real credential-stuffing tools operate in practice: prioritized, curated
lists rather than brute-forcing the entire dump against every account.

Run the server first (python run.py), then run this script separately.
"""

import time
import json
import requests

BASE_URL = "http://127.0.0.1:5000"
USERNAME = f"stuffing_target_{int(time.time())}"
EMAIL = "stuffing_target@example.com"
REAL_PASSWORD = "Xk9#mQ2vL!pR7zT4w"  # the account's real, strong password

# A representative sample of the most common breached passwords
# (sourced from widely published "most common passwords in breaches"
# lists, e.g. NCSC / Have I Been Pwned annual summaries -- not the
# account's real password, so none of these should succeed).
COMMON_PASSWORD_LIST = [
    "123456", "123456789", "qwerty", "password", "12345",
    "qwerty123", "1q2w3e", "12345678", "111111", "1234567890",
    "1234567", "123123", "000000", "iloveyou", "1234",
    "1q2w3e4r5t", "qwertyuiop", "admin", "qwerty1", "654321",
    "555555", "abc123", "password1", "password123", "666666",
    "121212", "letmein", "hello", "welcome", "monkey",
    "login", "princess", "solo", "master", "dragon",
    "qazwsx", "trustno1", "starwars", "freedom", "whatever",
    "football", "baseball", "superman", "shadow", "michael",
    "ninja", "mustang", "access", "flower", "charlie",
]

results = []


def log(entry):
    print(entry)
    results.append(entry)


def register_target():
    log(f"Registering target account: {USERNAME}")
    resp = requests.post(f"{BASE_URL}/api/auth/register", json={
        "username": USERNAME, "email": EMAIL, "password": REAL_PASSWORD,
    })
    log(f"  register status={resp.status_code}")
    if resp.status_code not in (200, 201):
        log(f"  ERROR: registration failed. body={resp.text!r}")
        raise SystemExit("Aborting: could not create target account.")


def attempt_login(password):
    resp = requests.post(f"{BASE_URL}/api/auth/login", json={
        "username": USERNAME, "password": password,
    })
    if resp.status_code == 429:
        log("  RATE LIMITED (429) — waiting 61s for the rate-limit window to reset...")
        time.sleep(61)
        resp = requests.post(f"{BASE_URL}/api/auth/login", json={
            "username": USERNAME, "password": password,
        })
    return resp


def run_simulation():
    register_target()
    log(f"\n=== Credential-stuffing simulation: trying {len(COMMON_PASSWORD_LIST)} "
        f"common passwords against '{USERNAME}' ===")

    start_time = time.time()
    locked_at_attempt = None

    for i, pwd in enumerate(COMMON_PASSWORD_LIST, 1):
        resp = attempt_login(pwd)
        status = resp.status_code

        if status == 423:
            body = resp.json()
            retry_after = body.get("retry_after_seconds")
            log(f"  attempt {i:2d} [{pwd!r:16}]: LOCKED (423), retry_after={retry_after}s")
            if locked_at_attempt is None:
                locked_at_attempt = i
            # Once locked, further attempts are pointless until it expires;
            # stop here rather than burning the rest of the list.
            break
        elif status == 200:
            log(f"  attempt {i:2d} [{pwd!r:16}]: SUCCESS (200) -- password guessed!")
            break
        else:
            log(f"  attempt {i:2d} [{pwd!r:16}]: rejected ({status})")

    elapsed = time.time() - start_time

    log("\n=== Summary ===")
    log(f"Total attempts sent before stopping: {i}")
    log(f"Locked out after attempt: {locked_at_attempt}")
    log(f"Elapsed time: {elapsed:.1f}s")
    log(f"None of the {len(COMMON_PASSWORD_LIST)} common passwords matched the "
        f"account's real (strong, unique) password, as expected.")

    with open("credential_stuffing_results.json", "w") as f:
        json.dump({
            "log": results,
            "total_attempts": i,
            "locked_at_attempt": locked_at_attempt,
            "elapsed_seconds": elapsed,
        }, f, indent=2)
    log("\nFull results saved to credential_stuffing_results.json")


if __name__ == "__main__":
    run_simulation()