"""Multi-gigabyte evidence (``pytest -m slow``; size via CUSTODY_LARGE_GB, default 10).

Uses sparse files so a 50 GB "disk" costs no disk space; random blocks are
written at a few offsets so chunks differ. Hashing still reads every byte.
"""

from __future__ import annotations

import os
import random
import time

import pytest

from custodychain import keys
from custodychain.hasher import CHUNK_SIZE, hash_file
from custodychain.ledger import Ledger
from custodychain.merkle import inclusion_proof
from custodyverify import tree
from custodyverify.check import CaseVerifier

GB = 10**9


@pytest.mark.slow
def test_large_image_inclusion_proof_and_flip(tmp_path):
    size = int(float(os.environ.get("CUSTODY_LARGE_GB", "10")) * GB)
    path = tmp_path / "large.img"
    with open(path, "wb") as fh:
        fh.truncate(size)
        rnd = random.Random(7)
        for _ in range(64):
            fh.seek(rnd.randrange(0, size - 4096))
            fh.write(os.urandom(4096))
    workers = max(1, (os.cpu_count() or 2) - 1)
    t0 = time.perf_counter()
    result = hash_file(path, workers=workers, digests=("sha256",))
    t_hash = time.perf_counter() - t0
    n = len(result.leaves)
    assert n == (size + CHUNK_SIZE - 1) // CHUNK_SIZE

    # inclusion proof for an arbitrary chunk verifies in the independent verifier
    idx = random.Random(1).randrange(n)
    proof = inclusion_proof(result.leaves, idx)
    assert tree.verify_inclusion(result.leaves[idx], idx, n, proof, result.root)
    assert len(proof) <= n.bit_length()

    admin = keys.generate("admin", "admin", tmp_path / "admin.key")
    led = Ledger.create(tmp_path / "case.db", "LARGE", "large image", admin)
    led.record_exhibit(admin, "acquire", "EX-L", "large image", result)
    led.close()

    offset = random.Random(2).randrange(size)
    with open(path, "r+b") as fh:
        fh.seek(offset)
        b = fh.read(1)
        fh.seek(offset)
        fh.write(bytes([b[0] ^ 0x80]))
    t0 = time.perf_counter()
    report = CaseVerifier(tmp_path / "case.db", {"EX-L": path}).run()
    t_verify = time.perf_counter() - t0
    ex = next(e for e in report["exhibits"] if e["id"] == "EX-L")
    assert ex["failing_chunks"] == [offset // CHUNK_SIZE]
    print(f"\n{size / GB:.0f} GB: {n} chunks, hashed in {t_hash:.1f}s ({size / GB / t_hash:.2f} GB/s, {workers} workers); "
          f"flipped byte at {offset} -> verifier named chunk {offset // CHUNK_SIZE} after {t_verify:.1f}s")
