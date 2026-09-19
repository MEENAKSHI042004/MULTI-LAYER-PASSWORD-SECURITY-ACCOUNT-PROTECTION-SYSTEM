# Load Testing: Per-User Rate Limiting Under Concurrent Attack

## Objective

Earlier testing (unit tests, the manual brute-force simulation, and
Chinmayi's credential-stuffing simulation) confirmed that account lockout
and per-username rate limiting work correctly against *sequential* login
attempts. This test asks a different question: does per-username rate
limiting hold up when many attackers hit the same account *concurrently and
at high volume*, rather than one attempt at a time? Reading the code and
running sequential tests cannot answer this on its own -- only load-testing
a live instance can.

## Method

A dedicated Locust load-test script (`locustfile.py`) simulates many
concurrent "attackers", each repeatedly submitting a wrong password for a
single target account (`loadtest_target`), with a short random delay
(0.1-0.5s) between each attempt per simulated user to approximate realistic
automated-attack pacing rather than an unrealistic tight loop.

**Configuration:**
- 50 concurrent simulated users
- Spawn rate: 10 users/second (ramp-up)
- Duration: 45 seconds
- Target endpoint: `POST /api/auth/login`, always with the correct
  username and a wrong password

## Results

| Metric | Value |
|---|---|
| Total requests sent | 6,914 |
| Successful auth attempts recorded (401 - wrong password) | 5 |
| Rate-limited (429) | 6,909 |
| Server errors (500) | **0** |
| Median response time | 2 ms |
| 95th percentile response time | 6 ms |
| Max response time | 942 ms |
| Throughput | ~157 requests/second |

## Analysis

**The rate limiter engaged almost immediately and held for the entire
run.** Only the first 5 requests reached the actual login/lockout logic and
received a genuine `401 Unauthorized`; every one of the remaining 6,909
requests -- across 50 concurrent simulated attackers over 45 seconds -- was
rejected at the rate-limiter layer with `429 Too Many Requests` before ever
reaching the password-comparison code. This is the intended behaviour:
`RATELIMIT_LOGIN_PER_USERNAME` is account-scoped, so it does not matter how
many different simulated "attackers" (i.e. concurrent connections) are
involved -- they are all attempting to guess the same account's password,
so they all draw from the same limited budget.

**No server errors occurred at any point.** A 500 error under load would
have indicated the app failing/crashing under concurrent pressure rather
than actively defending itself; zero were observed across 6,914 requests.

**Response times stayed low under load**, with a 2ms median and 6ms
95th-percentile response, confirming the rate-limiter check itself is cheap
and does not introduce a meaningful performance penalty even at ~157
requests/second. The single 942ms outlier (visible only at the 99.9th
percentile) is consistent with a one-off garbage-collection pause or SQLite
write-lock contention during ramp-up, not a systemic issue -- it did not
recur and did not affect the median or 95th-percentile figures.

**This complements, rather than duplicates, the earlier brute-force and
credential-stuffing simulations.** Those confirmed *sequential* correctness
(the lockout counter increments correctly, the duration doubles correctly).
This test confirms the *concurrent, high-volume* case: many simultaneous
connections attacking one account are all correctly throttled by the same
per-username limit, with no request able to "sneak through" a race
condition in the limiter under load, and without the server itself
buckling under the request volume.

## Reproducing this test

```bash
pip install locust
python run.py &
locust -f locustfile.py --host=http://127.0.0.1:5000 \
    --users 50 --spawn-rate 10 --run-time 45s --headless --csv=loadtest
```

Raw results are saved alongside this document as `loadtest_stats.csv` and
`loadtest_failures.csv`.
