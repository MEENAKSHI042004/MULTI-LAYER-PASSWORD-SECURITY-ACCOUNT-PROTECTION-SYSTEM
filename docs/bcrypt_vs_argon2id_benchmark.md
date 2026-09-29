# Bcrypt vs Argon2id Benchmark

Measured on this machine, 20 runs per algorithm, using this project's
actual hashing settings (argon2-cffi `PasswordHasher()` defaults; bcrypt with
work factor 12).

| Algorithm | Operation | Avg (ms) | Min (ms) | Max (ms) |
|-----------|-----------|----------|----------|----------|
| Argon2id  | Hash      | 393.41 | 208.26 | 903.65 |
| Argon2id  | Verify    | 380.97 | 203.52 | 624.00 |
| bcrypt    | Hash      | 787.26 | 698.18 | 1046.84 |
| bcrypt    | Verify    | 769.53 | 695.99 | 922.18 |

**Why this matters:** Argon2id is memory-hard -- it deliberately uses a
configurable amount of RAM per hash, not just CPU time. This makes it far
more expensive to parallelize on GPUs/ASICs than bcrypt, which is CPU-bound
and cheaper to brute-force at scale despite similar or even faster wall-clock
time on a single machine. A small extra cost per legitimate login is a
worthwhile tradeoff for making large-scale offline cracking attempts
significantly more expensive for an attacker.
