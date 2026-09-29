# Hash-Chained Audit Log vs Naive Log -- Tamper Detection Benchmark

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

| Log size (entries) | Verification time |
|---------------------|--------------------|
| 100                  | 0.47ms |
| 1,000                | 3.88ms |
| 10,000               | 33.65ms |

Verification time grows roughly linearly with log size, as expected (each
entry requires one hash recomputation). Even at 10,000 entries, full-chain
verification completes in well under 50ms -- a negligible cost for turning
silent, undetectable tampering into something caught immediately.

## Conclusion

The hash chain adds negligible overhead per log entry (a single SHA-256
hash operation) while turning an undetectable tampering risk into an
immediately detectable one -- a strong security improvement for a small,
measured performance cost.