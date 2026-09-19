"""
Locust load test: simulates many concurrent attackers hammering the login
endpoint with wrong passwords for a single account, to verify per-user rate
limiting and account lockout hold up under real concurrent load rather than
being asserted only from a code read.

Run with (see docs/load-testing.md for the full write-up):
    locust -f locustfile.py --host=http://127.0.0.1:5000 \
        --users 50 --spawn-rate 10 --run-time 1m --headless --csv=loadtest
"""

from locust import HttpUser, task, between


class LoginAttacker(HttpUser):
    wait_time = between(0.1, 0.5)

    @task
    def guess_password(self):
        self.client.post(
            "/api/auth/login",
            json={"username": "loadtest_target", "password": "wrongpassword123"},
            name="/api/auth/login [wrong password]",
        )
