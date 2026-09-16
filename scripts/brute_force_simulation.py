"""
Brute-force lockout simulation for MLPSAPS.
Hammers the /login endpoint with wrong passwords against a live server
and records whether the account locks and whether the lockout duration
grows on repeat offenses, as the security design intends.

Run the server first (python run.py), then run this script separately.
"""

import time
import json
import requests

BASE_URL = "http://127.0.0.1:5000"
USERNAME = f"attack_target_{int(time.time())}"
EMAIL = f"{USERNAME}@example.com"
PASSWORD = "Str0ng!Passw0rd"
WRONG_PASSWORD = "totally-wrong-password"

MAX_FAILED_ATTEMPTS = 5      # from config.py
NUM_LOCKOUT_ROUNDS = 3       # how many repeat lockouts to trigger and observe

results = []


def log(entry):
    print(entry)
    results.append(entry)


def register_target():
    resp = requests.post(f"{BASE_URL}/api/auth/register", json={
        "username": USERNAME, "email": EMAIL, "password": PASSWORD
    })
    log(f"[setup] register -> {resp.status_code}")
    if resp.status_code not in (200, 201):
        log(f"  ERROR: registration failed. body={resp.text!r}")
        raise SystemExit("Aborting: could not create target account.")


def attempt_login(password):
    resp = requests.post(f"{BASE_URL}/api/auth/login", json={
        "username": USERNAME, "password": password
    })
    if resp.status_code == 429:
        log("  RATE LIMITED (429) — waiting 61s for the rate-limit window to reset...")
        time.sleep(61)
        resp = requests.post(f"{BASE_URL}/api/auth/login", json={
            "username": USERNAME, "password": password
        })
    return resp


def run_round(round_num):
    log(f"\n=== Round {round_num}: sending {MAX_FAILED_ATTEMPTS} wrong-password attempts ===")
    for i in range(1, MAX_FAILED_ATTEMPTS + 1):
        resp = attempt_login(WRONG_PASSWORD)
        log(f"  attempt {i}: status={resp.status_code} time={time.strftime('%H:%M:%S')}")

    # This next attempt (even with the CORRECT password) should be blocked.
    resp = attempt_login(PASSWORD)

    try:
        body = resp.json()
    except ValueError:
        log(f"  ERROR: server did not return JSON. status={resp.status_code} body={resp.text!r}")
        return None

    retry_after = body.get("retry_after_seconds")
    log(f"  post-lockout check: status={resp.status_code} retry_after_seconds={retry_after}")

    if resp.status_code == 423:
        log(f"  RESULT: account locked. Waiting {retry_after}s for lockout to expire...")
        time.sleep(retry_after + 1)
        return retry_after
    else:
        log("  RESULT: account was NOT locked (unexpected).")
        return None


def main():
    log(f"Using username: {USERNAME}")
    register_target()

    durations = []
    for round_num in range(1, NUM_LOCKOUT_ROUNDS + 1):
        duration = run_round(round_num)
        durations.append(duration)

    log("\n=== Summary ===")
    for i, d in enumerate(durations, 1):
        log(f"Lockout {i} duration: {d} seconds")

    if all(durations):
        growing = all(durations[i] > durations[i - 1] for i in range(1, len(durations)))
        log(f"Duration increased each round: {growing}")

    with open("brute_force_results.json", "w") as f:
        json.dump({"log": results, "durations": durations}, f, indent=2)
    log("\nFull results saved to brute_force_results.json")


if __name__ == "__main__":
    main()