# Benchmarks

Machine: Apple M1 Pro (10 cores), macOS 26.5, Python 3.12, OpenSSL 3.6.3, `blake3` 1.0.
Files are in the page cache unless stated, so these numbers are CPU throughput. On a real
acquisition the source disk or write-blocker (typically 0.2–3 GB/s) is the limit.

Reproduce: `custody bench --size-gib 4 --workers 1,2,4,8`

## Hash primitives and Merkle leaf hashing (4 GiB file)

| Mode | Hash | Processes | Seconds | GB/s |
|---|---|---|---|---|
| whole-file, one stream | SHA-256 | 1 | 2.74 | 1.57 |
| whole-file, one stream | SHA-1 | 1 | 2.72 | 1.58 |
| whole-file, one stream | MD5 | 1 | 7.17 | 0.60 |
| Merkle leaves (4 MiB) | SHA-256 | 1 | 2.59 | 1.66 |
| Merkle leaves (4 MiB) | SHA-256 | 2 | 1.86 | 2.31 |
| Merkle leaves (4 MiB) | SHA-256 | 4 | 1.24 | 3.47 |
| Merkle leaves (4 MiB) | SHA-256 | 8 | 1.09 | 3.95 |
| Merkle leaves (4 MiB) | BLAKE3 | 1 | 3.22 | 1.33 |
| Merkle leaves (4 MiB) | BLAKE3 | 2 | 2.11 | 2.04 |
| Merkle leaves (4 MiB) | BLAKE3 | 4 | 1.43 | 3.01 |
| Merkle leaves (4 MiB) | BLAKE3 | 8 | 1.28 | 3.35 |

**SHA-256 beats BLAKE3 here.** The M1's ARMv8 SHA-2 instructions (used by OpenSSL) outrun
the `blake3` package's single-threaded NEON path. BLAKE3's usual advantage comes from
its internal tree parallelism, and leaf-level multiprocessing already provides that. On
x86 machines without SHA extensions the result is likely to flip. SHA-256 stays the default
because courts and other tools already recognise it.

## What an acquisition costs (4 GiB, 8 leaf processes)

| Records | Seconds | GB/s |
|---|---|---|
| Merkle root + whole-file SHA-256 + SHA-1 + MD5 (default) | 7.80 | 0.55 |
| Merkle root + whole-file SHA-256 | 3.17 | 1.36 |
| Merkle root only | 0.89 | 4.80 |

Whole-file digests are inherently sequential. Each one runs in its own process alongside
the leaf workers, so acquisition goes as fast as the slowest digest. **MD5 is the
bottleneck**, and the legacy digests together cost about 9× the time of the Merkle root
alone. They stay on by default because other tools and courts still expect them;
`--digests sha256` or `--digests none` drops them.

## Large images (sparse files, every byte still hashed)

| Image | Chunks | Hash (9 processes, + whole-file SHA-256) | Inclusion proof | Byte flipped → verifier result |
|---|---|---|---|---|
| 10 GB | 2,385 | 7.4 s (1.34 GB/s) | ≤ 12 hashes, verifies in the independent verifier | named chunk 57 (the right one) after a 10.7 s single-process re-hash |
| 50 GB | 11,921 | 36.0 s (1.39 GB/s) | ≤ 14 hashes | named chunk 1,081 (the right one) after a 54.3 s re-hash |

Reproduce: `CUSTODY_LARGE_GB=50 pytest -m slow -s tests/test_large.py`

The independent verifier re-hashes in a single process on purpose: it is the
simplest code path and the one a court expert would read.
