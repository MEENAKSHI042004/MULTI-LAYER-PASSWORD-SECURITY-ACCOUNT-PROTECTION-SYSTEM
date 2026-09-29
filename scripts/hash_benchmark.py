"""
Bcrypt vs Argon2id Hashing Benchmark.

Measures real timing for hashing and verifying passwords with both
algorithms, using this project's actual settings (argon2-cffi's
PasswordHasher() defaults, matching app/security/hashing.py; bcrypt with
its standard work factor of 12, the common production default).

This produces real numbers to back the design decision documented in
SECURITY.md (Argon2id chosen as memory-hard, current OWASP recommendation),
rather than just asserting it without evidence.
"""

import time
import statistics

import bcrypt
from argon2 import PasswordHasher

ph = PasswordHasher()  # same defaults as app/security/hashing.py

TEST_PASSWORD = "MyStrongPass123!"
NUM_RUNS = 20  # hash/verify this many times per algorithm, report the average


def benchmark_argon2id():
    hash_times = []
    verify_times = []

    for _ in range(NUM_RUNS):
        start = time.perf_counter()
        hashed = ph.hash(TEST_PASSWORD)
        hash_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        ph.verify(hashed, TEST_PASSWORD)
        verify_times.append(time.perf_counter() - start)

    return hash_times, verify_times


def benchmark_bcrypt():
    hash_times = []
    verify_times = []

    for _ in range(NUM_RUNS):
        start = time.perf_counter()
        hashed = bcrypt.hashpw(TEST_PASSWORD.encode("utf-8"), bcrypt.gensalt(rounds=12))
        hash_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        bcrypt.checkpw(TEST_PASSWORD.encode("utf-8"), hashed)
        verify_times.append(time.perf_counter() - start)

    return hash_times, verify_times


def summarize(label, times):
    avg = statistics.mean(times) * 1000  # convert to ms
    minimum = min(times) * 1000
    maximum = max(times) * 1000
    print(f"  {label}: avg={avg:.2f}ms  min={minimum:.2f}ms  max={maximum:.2f}ms")
    return avg


def main():
    print(f"Benchmarking {NUM_RUNS} runs per algorithm...\n")

    print("=== Argon2id (this project's default, via argon2-cffi PasswordHasher()) ===")
    argon2_hash_times, argon2_verify_times = benchmark_argon2id()
    argon2_hash_avg = summarize("Hash", argon2_hash_times)
    argon2_verify_avg = summarize("Verify", argon2_verify_times)

    print("\n=== bcrypt (legacy algorithm, work factor 12) ===")
    bcrypt_hash_times, bcrypt_verify_times = benchmark_bcrypt()
    bcrypt_hash_avg = summarize("Hash", bcrypt_hash_times)
    bcrypt_verify_avg = summarize("Verify", bcrypt_verify_times)

    print("\n=== Summary ===")
    print(f"Argon2id hash:   {argon2_hash_avg:.2f}ms avg")
    print(f"bcrypt hash:     {bcrypt_hash_avg:.2f}ms avg")
    print(f"Argon2id verify: {argon2_verify_avg:.2f}ms avg")
    print(f"bcrypt verify:   {bcrypt_verify_avg:.2f}ms avg")

    results_md = f"""# Bcrypt vs Argon2id Benchmark

Measured on this machine, {NUM_RUNS} runs per algorithm, using this project's
actual hashing settings (argon2-cffi `PasswordHasher()` defaults; bcrypt with
work factor 12).

| Algorithm | Operation | Avg (ms) | Min (ms) | Max (ms) |
|-----------|-----------|----------|----------|----------|
| Argon2id  | Hash      | {argon2_hash_avg:.2f} | {min(argon2_hash_times)*1000:.2f} | {max(argon2_hash_times)*1000:.2f} |
| Argon2id  | Verify    | {argon2_verify_avg:.2f} | {min(argon2_verify_times)*1000:.2f} | {max(argon2_verify_times)*1000:.2f} |
| bcrypt    | Hash      | {bcrypt_hash_avg:.2f} | {min(bcrypt_hash_times)*1000:.2f} | {max(bcrypt_hash_times)*1000:.2f} |
| bcrypt    | Verify    | {bcrypt_verify_avg:.2f} | {min(bcrypt_verify_times)*1000:.2f} | {max(bcrypt_verify_times)*1000:.2f} |

**Why this matters:** Argon2id is memory-hard -- it deliberately uses a
configurable amount of RAM per hash, not just CPU time. This makes it far
more expensive to parallelize on GPUs/ASICs than bcrypt, which is CPU-bound
and cheaper to brute-force at scale despite similar or even faster wall-clock
time on a single machine. A small extra cost per legitimate login is a
worthwhile tradeoff for making large-scale offline cracking attempts
significantly more expensive for an attacker.
"""

    with open("docs/bcrypt_vs_argon2id_benchmark.md", "w") as f:
        f.write(results_md)

    print("\nResults saved to docs/bcrypt_vs_argon2id_benchmark.md")


if __name__ == "__main__":
    main()