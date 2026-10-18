"""Stream evidence into fixed-size chunks and build its Merkle tree.

* 4 MiB leaves by default, so one flipped byte is localised to a 4 MiB range
  and an inclusion proof for any chunk is ~log2(n) hashes.
* Parallel: worker processes hash disjoint byte ranges straight from the
  file; the parent concurrently computes the whole-file SHA-256 / SHA-1 /
  MD5 that courts and other tools expect.
* Resumable: completed leaves are checkpointed through a callback (the
  ledger persists them in SQLite), so a crash at 400 GB resumes at 400 GB.
  The whole-file digests cannot be resumed (hash state is not portable), so
  they are recomputed in full on resume.
* E01 images are hashed as decoded *media* (what the suspect drive held),
  and the image's own embedded MD5 / SHA-1 are checked against it.
"""

from __future__ import annotations

import hashlib
import os
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from custodychain import ewf
from custodychain.merkle import HASHES, leaf_hash, root_from_leaf_hashes

CHUNK_SIZE = 4 * 1024 * 1024
BATCH_CHUNKS = 16  # 64 MiB of work per task


class EvidenceChanged(Exception):
    """The file changed while it was being hashed."""


@dataclass
class HashResult:
    path: str
    kind: str  # raw | e01
    size: int
    chunk_size: int
    alg: str
    leaves: list[bytes]
    root: bytes
    digests: dict[str, str] = field(default_factory=dict)
    ewf: dict | None = None
    seconds: float = 0.0
    workers: int = 1
    resumed_from: int = 0

    @property
    def gbps(self) -> float:
        return (self.size / 1e9) / self.seconds if self.seconds else 0.0


def _hash_range(path: str, start_chunk: int, n_chunks: int, chunk_size: int, alg: str) -> list[bytes]:
    h = HASHES[alg]
    out = []
    with open(path, "rb", buffering=0) as fh:
        fh.seek(start_chunk * chunk_size)
        for _ in range(n_chunks):
            data = fh.read(chunk_size)
            if not data:
                break
            out.append(leaf_hash(data, h))
    return out


def _file_digests(path: Path, names: Iterable[str], block: int = 8 << 20) -> dict[str, str]:
    hashers = {n: hashlib.new(n) for n in names}
    with open(path, "rb", buffering=0) as fh:
        while True:
            data = fh.read(block)
            if not data:
                break
            for hh in hashers.values():
                hh.update(data)
    return {n: hh.hexdigest() for n, hh in hashers.items()}


def readonly_status(path: Path) -> dict[str, bool]:
    """Is the evidence protected against accidental writes?"""
    st = os.statvfs(path)
    return {
        "mount_read_only": bool(st.f_flag & getattr(os, "ST_RDONLY", 1)),
        "file_writable_by_us": os.access(path, os.W_OK),
    }


def hash_file(
    path: Path,
    chunk_size: int = CHUNK_SIZE,
    alg: str = "sha256",
    workers: int = 1,
    digests: Iterable[str] = ("sha256", "sha1", "md5"),
    existing_leaves: list[bytes] | None = None,
    on_leaves: Callable[[int, list[bytes]], None] | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> HashResult:
    """Hash a raw image (or any file). ``existing_leaves`` resumes a crashed run."""
    if alg not in HASHES:
        raise ValueError(f"unknown hash {alg}")
    path = Path(path)
    before = path.stat()
    size = before.st_size
    n_chunks = max(1, (size + chunk_size - 1) // chunk_size) if size else 0
    leaves: list[bytes] = list(existing_leaves or [])
    resumed_from = len(leaves)
    start = time.perf_counter()
    digest_names = list(digests)

    batches = [(i, min(BATCH_CHUNKS, n_chunks - i)) for i in range(resumed_from, n_chunks, BATCH_CHUNKS)]
    if workers <= 1:
        for first, count in batches:
            new = _hash_range(str(path), first, count, chunk_size, alg)
            leaves.extend(new)
            if on_leaves:
                on_leaves(first, new)
            if progress:
                progress(min((first + count) * chunk_size, size), size)
        file_digests = _file_digests(path, digest_names) if digest_names else {}
    else:
        with ProcessPoolExecutor(max_workers=workers + len(digest_names)) as pool:
            # Whole-file digests are inherently sequential, so each algorithm gets its own
            # process and its own read of the file; they start first and run alongside the
            # leaf workers. (MD5 alone is ~0.6 GB/s on an M1 Pro: computing all three in
            # one stream would cap acquisition at ~0.35 GB/s.)
            digest_futures = [pool.submit(_file_digests, path, [name]) for name in digest_names]
            futures = [pool.submit(_hash_range, str(path), first, count, chunk_size, alg) for first, count in batches]
            for (first, count), fut in zip(batches, futures):
                new = fut.result()
                leaves.extend(new)
                if on_leaves:
                    on_leaves(first, new)
                if progress:
                    progress(min((first + count) * chunk_size, size), size)
            file_digests = {}
            for fut in digest_futures:
                file_digests.update(fut.result())

    after = path.stat()
    if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
        raise EvidenceChanged(f"{path} changed while it was being hashed (size/mtime differ)")
    if len(leaves) != n_chunks:
        raise EvidenceChanged(f"{path}: expected {n_chunks} chunks, hashed {len(leaves)}")
    h = HASHES[alg]
    return HashResult(
        path=str(path), kind="raw", size=size, chunk_size=chunk_size, alg=alg, leaves=leaves,
        root=root_from_leaf_hashes(leaves, h), digests=file_digests,
        seconds=time.perf_counter() - start, workers=workers, resumed_from=resumed_from,
    )


def hash_e01(path: Path, chunk_size: int = CHUNK_SIZE, alg: str = "sha256",
             progress: Callable[[int, int], None] | None = None) -> HashResult:
    """Hash the decoded media of an E01 image and check its embedded hashes."""
    image = ewf.open_e01(Path(path))
    h = HASHES[alg]
    start = time.perf_counter()
    leaves: list[bytes] = []
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    done = 0
    for block in image.iter_media(chunk_size):
        leaves.append(leaf_hash(block, h))
        md5.update(block)
        sha1.update(block)
        sha256.update(block)
        done += len(block)
        if progress:
            progress(done, image.media_size)
    if done != image.media_size:
        raise EvidenceChanged(f"{path}: decoded {done} bytes, volume section says {image.media_size}")
    computed = {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}
    ewf_info = {
        "segments": [p.name for p in image.paths],
        "container_bytes": sum(p.stat().st_size for p in image.paths),
        "ewf_chunk_size": image.chunk_size,
        "stored_md5": image.stored_md5,
        "stored_sha1": image.stored_sha1,
        "md5_match": None if image.stored_md5 is None else image.stored_md5 == computed["md5"],
        "sha1_match": None if image.stored_sha1 is None else image.stored_sha1 == computed["sha1"],
        "header": image.header,
    }
    cross = ewf.libewf_cross_check(Path(path))
    if cross is not None:
        ewf_info["libewf"] = {k: v for k, v in cross.items() if k != "stored"}
        if "md5" in cross:
            ewf_info["libewf"]["agrees"] = cross["md5"] == computed["md5"]
    return HashResult(
        path=str(path), kind="e01", size=image.media_size, chunk_size=chunk_size, alg=alg, leaves=leaves,
        root=root_from_leaf_hashes(leaves, h), digests=computed, ewf=ewf_info,
        seconds=time.perf_counter() - start,
    )


def hash_evidence(path: Path, **kwargs) -> HashResult:
    path = Path(path)
    if ewf.is_ewf(path):
        allowed = {k: v for k, v in kwargs.items() if k in ("chunk_size", "alg", "progress")}
        return hash_e01(path, **allowed)
    return hash_file(path, **kwargs)
