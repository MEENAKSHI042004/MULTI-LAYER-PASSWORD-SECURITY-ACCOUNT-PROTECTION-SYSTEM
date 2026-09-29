"""
Hash-Chained Audit Log vs Naive Log -- Tamper-Detection Benchmark.

Demonstrates, with real generated data and real timing:
  1. A naive log (plain rows, no hashing) has NO way to detect that a row
     was altered after the fact -- tampering is silent and undetectable.
  2. This project's hash-chained log (same logic as
     app/security/audit_logger.py) detects tampering immediately, and
     reports exactly which entry was altered.
  3. Verifying the hash chain stays fast even as the log grows, so the
     security benefit doesn't come with an unreasonable performance cost.

This script is self-contained -- it does not touch the real application
database. All entries here are generated in memory for measurement only.
"""

import hashlib
import time
import copy


class LogEntry:
    def __init__(self, entry_id, event_type, details, prev_hash=None):
        self.id = entry_id
        self.event_type = event_type
        self.details = details
        self.prev_hash = prev_hash
        self.hash = None


def compute_hash(entry):
    """Same approach as app/security/audit_logger.py: combine this entry's
    own fields with the previous entry's hash, then hash all of it together."""
    raw = f"{entry.id}|{entry.event_type}|{entry.details}|{entry.prev_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_naive_log(n):
    """Plain list of entries -- no hash, no chain. Nothing links one entry
    to the next, so nothing would notice if a row's contents changed."""
    return [LogEntry(i, "login_success", f"user_{i}") for i in range(n)]


def build_hash_chained_log(n):
    """Each entry's hash depends on its own data AND the previous entry's
    hash -- exactly how app/security/audit_logger.py builds the real chain."""
    log = []
    prev_hash = None
    for i in range(n):
        entry = LogEntry(i, "login_success", f"user_{i}", prev_hash=prev_hash)
        entry.hash = compute_hash(entry)
        log.append(entry)
        prev_hash = entry.hash
    return log


def verify_naive_log(log):
    """A naive log has nothing to check against -- there is no way to prove
    a row wasn't altered after being written. Always 'passes' silently."""
    return True, None  # can never detect tampering -- that's the whole point


def verify_hash_chain(log):
    """Recompute every hash from scratch and confirm the chain still lines
    up. Returns (is_intact, broken_at_id)."""
    expected_prev_hash = None
    for entry in log:
        if entry.prev_hash != expected_prev_hash:
            return False, entry.id
        if compute_hash(entry) != entry.hash:
            return False, entry.id
        expected_prev_hash = entry.hash
    return True, None


def tamper(log, target_id):
    """Simulates an attacker with direct database access silently editing
    one row -- exactly what a hash chain is meant to catch."""
    tampered = copy.deepcopy(log)
    tampered[target_id].event_type = "HACKED"
    return tampered


def demonstrate_tamper_detection():
    print("=== Tamper Detection Demo (10 entries, tampering with entry #5) ===\n")

    naive = build_naive_log(10)
    chained = build_hash_chained_log(10)

    tampered_naive = tamper(naive, 5)
    tampered_chained = tamper(chained, 5)

    naive_ok, _ = verify_naive_log(tampered_naive)
    chained_ok, broken_at = verify_hash_chain(tampered_chained)

    print(f"Naive log after tampering:        intact={naive_ok}  (WRONG -- tampering went undetected)")
    print(f"Hash-chained log after tampering: intact={chained_ok}  broken_at_entry={broken_at}  (correctly caught)")


def benchmark_verification_speed():
    print("\n=== Verification Speed as Log Grows ===\n")
    sizes = [100, 1000, 10000]

    for n in sizes:
        chained = build_hash_chained_log(n)

        start = time.perf_counter()
        verify_hash_chain(chained)
        elapsed = (time.perf_counter() - start) * 1000  # ms

        print(f"  {n:>6} entries -> verify took {elapsed:.2f}ms")


def main():
    demonstrate_tamper_detection()
    benchmark_verification_speed()

    results_md = """# Hash-Chained Audit Log vs Naive Log -- Tamper Detection Benchmark

## The core problem

A naive audit log (plain rows in a database table, no hashing) has **no way
to detect** that a row was altered after being written. Someone with direct
database access can silently edit or delete a log entry, and the application
has no mechanism to notice.

## The fix

Each log entry's hash is calculated from its own fields **plus** the hash of
the entry immediately before it (see `app/security/audit_logger.py`). This
creates a chain: editing any row breaks the chain from that point forward,
and verification (`verify_chain()`) detects exactly which entry was altered.

## Demonstrated result

| Log type       | Tampered with entry #5 | Detected? |
|-----------------|------------------------|-----------|
| Naive log        | Yes                    | **No** -- tampering is silent |
| Hash-chained log | Yes                    | **Yes** -- flagged at entry #5 |

## Verification performance as the log grows

Verifying the entire chain means recomputing every hash from scratch, so
performance was measured at increasing log sizes to confirm this stays
practical:

*(see console output / re-run `scripts/audit_log_benchmark.py` for exact
numbers on this machine)*

## Conclusion

The hash chain adds negligible overhead per log entry (a single SHA-256
hash operation) while turning an undetectable tampering risk into an
immediately detectable one -- a strong security improvement for a small,
measured performance cost.
"""

    with open("docs/audit_log_tamper_benchmark.md", "w") as f:
        f.write(results_md)

    print("\nResults saved to docs/audit_log_tamper_benchmark.md")


if __name__ == "__main__":
    main()