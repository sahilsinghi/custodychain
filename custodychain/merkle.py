"""RFC 9162 (Certificate Transparency v2) Merkle trees.

Leaf and interior hashes are domain-separated - ``H(0x00 || leaf)`` and
``H(0x01 || left || right)`` - so an attacker cannot present an interior node
as a leaf (second-preimage attack on unbalanced trees). The tree shape is
the RFC's: split at the largest power of two smaller than ``n``.

Used twice: once per exhibit (leaves are 4 MiB chunks of the evidence) and
once for the custody log (leaves are signed ledger entries). Inclusion
proofs show a chunk or entry is in a tree; consistency proofs show a later
log is an append-only extension of an earlier one.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Sequence

HashFn = Callable[[bytes], bytes]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def blake3_hash(data: bytes) -> bytes:
    import blake3  # optional dependency

    return blake3.blake3(data).digest()


HASHES: dict[str, HashFn] = {"sha256": sha256, "blake3": blake3_hash}


def leaf_hash(data: bytes, h: HashFn = sha256) -> bytes:
    return h(b"\x00" + data)


def node_hash(left: bytes, right: bytes, h: HashFn = sha256) -> bytes:
    return h(b"\x01" + left + right)


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root_from_leaf_hashes(leaves: Sequence[bytes], h: HashFn = sha256) -> bytes:
    """MTH over already-hashed leaves; iterative, O(n) memory for the level."""
    n = len(leaves)
    if n == 0:
        return h(b"")
    # Build the RFC tree bottom-up: pairing left to right and promoting a
    # trailing odd node gives exactly the "largest power of two" split.
    level = list(leaves)
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1], h) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def _subtree(leaves: Sequence[bytes], lo: int, hi: int, h: HashFn) -> bytes:
    return root_from_leaf_hashes(leaves[lo:hi], h)


def inclusion_proof(leaves: Sequence[bytes], index: int, h: HashFn = sha256) -> list[bytes]:
    """RFC 9162 2.1.3.1 PATH(m, D[n]) over leaf hashes."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(f"leaf {index} outside tree of size {n}")

    def path(m: int, lo: int, hi: int) -> list[bytes]:
        size = hi - lo
        if size == 1:
            return []
        k = _split(size)
        if m < k:
            return path(m, lo, lo + k) + [_subtree(leaves, lo + k, hi, h)]
        return path(m - k, lo + k, hi) + [_subtree(leaves, lo, lo + k, h)]

    return path(index, 0, n)


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes], root: bytes,
                     h: HashFn = sha256) -> bool:
    """RFC 9162 2.1.3.2 - ``leaf`` is the leaf hash."""
    if not 0 <= index < size:
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r, h)
            if not fn & 1:
                while fn & 1 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p, h)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_proof(leaves: Sequence[bytes], old_size: int, h: HashFn = sha256) -> list[bytes]:
    """RFC 9162 2.1.4.1 PROOF(m, D[n])."""
    n = len(leaves)
    if not 0 < old_size <= n:
        raise ValueError("need 0 < old_size <= new_size")

    def subproof(m: int, lo: int, hi: int, complete: bool) -> list[bytes]:
        size = hi - lo
        if m == size:
            return [] if complete else [_subtree(leaves, lo, hi, h)]
        k = _split(size)
        if m <= k:
            return subproof(m, lo, lo + k, complete) + [_subtree(leaves, lo + k, hi, h)]
        return subproof(m - k, lo + k, hi, False) + [_subtree(leaves, lo, lo + k, h)]

    if old_size == n:
        return []
    return subproof(old_size, 0, n, True)


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes,
                       proof: Sequence[bytes], h: HashFn = sha256) -> bool:
    """RFC 9162 2.1.4.2."""
    if old_size == new_size:
        return old_root == new_root and not proof
    if not 0 < old_size < new_size or not proof:
        return False
    path = list(proof)
    if old_size & (old_size - 1) == 0:  # exact power of two: old root is the first node
        path.insert(0, old_root)
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr, h)
            sr = node_hash(c, sr, h)
            if not fn & 1:
                while fn & 1 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c, h)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root
