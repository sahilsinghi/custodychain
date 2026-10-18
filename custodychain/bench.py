"""Hashing throughput on this machine: SHA-256 vs BLAKE3, 1..N processes."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

from custodychain.hasher import hash_file

BLOCK = 64 * 1024 * 1024


def make_file(path: Path, size: int) -> None:
    pattern = os.urandom(BLOCK)
    with open(path, "wb") as fh:
        left = size
        i = 0
        while left > 0:
            # vary each block so no two chunks are identical
            block = bytes([i & 0xFF]) + pattern[1:]
            fh.write(block[: min(left, BLOCK)])
            left -= BLOCK
            i += 1


def run_bench(size_gib: float, workers: list[int], scratch: Path, out: Path | None, console: Console) -> list[dict]:
    size = int(size_gib * (1 << 30))
    path = scratch / ".custody-bench.bin"
    console.print(f"writing {size_gib} GiB test file to {path} ...")
    make_file(path, size)
    rows = []
    try:
        for name in ("sha256", "md5", "sha1"):
            start = time.perf_counter()
            h = hashlib.new(name)
            with open(path, "rb", buffering=0) as fh:
                while chunk := fh.read(8 << 20):
                    h.update(chunk)
            sec = time.perf_counter() - start
            rows.append({"mode": f"whole-file {name} (1 stream)", "alg": name, "workers": 1, "seconds": sec,
                         "gbps": size / 1e9 / sec})
        algs = ["sha256"]
        try:
            import blake3  # noqa: F401

            algs.append("blake3")
        except ImportError:
            console.print("[yellow]blake3 not installed: skipping BLAKE3[/]")
        for alg in algs:
            for w in workers:
                start = time.perf_counter()
                res = hash_file(path, alg=alg, workers=w, digests=())
                sec = time.perf_counter() - start
                rows.append({"mode": "Merkle leaves (4 MiB)", "alg": alg, "workers": w, "seconds": sec,
                             "gbps": size / 1e9 / sec, "root": res.root.hex()[:16]})
    finally:
        path.unlink(missing_ok=True)
    table = Table("mode", "alg", "processes", "seconds", "GB/s")
    for r in rows:
        table.add_row(r["mode"], r["alg"], str(r["workers"]), f"{r['seconds']:.2f}", f"{r['gbps']:.2f}")
    console.print(table)
    if out:
        lines = ["| Mode | Hash | Processes | Seconds | GB/s |", "|---|---|---|---|---|"]
        lines += [f"| {r['mode']} | {r['alg']} | {r['workers']} | {r['seconds']:.2f} | {r['gbps']:.2f} |" for r in rows]
        out.write_text("\n".join(lines) + "\n")
    return rows
