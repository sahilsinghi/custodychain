"""RFC 9162 Merkle tree maths, written directly from the RFC's recursive definitions.

(Independent of the writer's iterative implementation; the tests check the
two agree with each other and with Certificate Transparency's test vectors.)
"""

from __future__ import annotations

import hashlib
from typing import Callable, Sequence

Hash = Callable[[bytes], bytes]


def h_sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def h_blake3(b: bytes) -> bytes:  # pragma: no cover - only if a case used blake3
    try:
        import blake3  # type: ignore
    except ImportError as exc:
        raise RuntimeError("this case uses BLAKE3 leaves; install the blake3 package to verify it") from exc
    return blake3.blake3(b).digest()


HASH_BY_NAME = {"sha256": h_sha256, "blake3": h_blake3}


def k_split(n: int) -> int:
    k = 1
    while 2 * k < n:
        k *= 2
    return k


def mth(leaf_hashes: Sequence[bytes], h: Hash = h_sha256) -> bytes:
    """MTH over pre-hashed leaves (leaf hash = H(0x00 || data))."""
    n = len(leaf_hashes)
    if n == 0:
        return h(b"")
    if n == 1:
        return leaf_hashes[0]
    k = k_split(n)
    return h(b"\x01" + mth(leaf_hashes[:k], h) + mth(leaf_hashes[k:], h))


def mth_large(leaf_hashes: Sequence[bytes], h: Hash = h_sha256) -> bytes:
    """Same result as ``mth`` without deep recursion (for 100k+ evidence chunks)."""
    stack: list[tuple[int, bytes]] = []  # (subtree size, hash), sizes strictly decreasing powers of two
    for leaf in leaf_hashes:
        node, size = leaf, 1
        while stack and stack[-1][0] == size:
            left = stack.pop()[1]
            node, size = h(b"\x01" + left + node), size * 2
        stack.append((size, node))
    if not stack:
        return h(b"")
    node = stack.pop()[1]
    while stack:
        node = h(b"\x01" + stack.pop()[1] + node)
    return node


def verify_consistency(m: int, n: int, old_root: bytes, new_root: bytes, proof: Sequence[bytes],
                       h: Hash = h_sha256) -> bool:
    """RFC 9162 2.1.4.2, step by step."""
    if m == n:
        return old_root == new_root and len(proof) == 0
    if m <= 0 or m > n or len(proof) == 0:
        return False
    path = list(proof)
    if m & (m - 1) == 0:
        path = [old_root] + path
    fn, sn = m - 1, n - 1
    while fn % 2 == 1:
        fn //= 2
        sn //= 2
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = h(b"\x01" + c + fr)
            sr = h(b"\x01" + c + sr)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            sr = h(b"\x01" + sr + c)
        fn //= 2
        sn //= 2
    return sn == 0 and fr == old_root and sr == new_root


def verify_inclusion(leaf: bytes, index: int, n: int, proof: Sequence[bytes], root: bytes, h: Hash = h_sha256) -> bool:
    if index >= n or index < 0:
        return False
    fn, sn, r = index, n - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = h(b"\x01" + p + r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            r = h(b"\x01" + r + p)
        fn //= 2
        sn //= 2
    return sn == 0 and r == root
