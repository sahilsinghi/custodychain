"""Property-based tests: any single-byte change must break verification."""

from __future__ import annotations

import hashlib
import os
import random

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from custodychain import canonical, merkle
from custodychain.hasher import hash_file
from custodyverify import tree

LEAVES = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43", b"\x50\x51\x52\x53\x54\x55\x56\x57",
          bytes(range(0x60, 0x70))]
CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def test_certificate_transparency_vectors_in_both_implementations():
    hashes = [merkle.leaf_hash(x) for x in LEAVES]
    for n in range(1, 9):
        assert merkle.root_from_leaf_hashes(hashes[:n]).hex() == CT_ROOTS[n - 1]
        assert tree.mth(hashes[:n]).hex() == CT_ROOTS[n - 1]
        assert tree.mth_large(hashes[:n]).hex() == CT_ROOTS[n - 1]
    assert merkle.root_from_leaf_hashes([]).hex() == hashlib.sha256(b"").hexdigest()


@given(st.lists(st.binary(max_size=40), min_size=1, max_size=70), st.data())
@settings(max_examples=150, deadline=None)
def test_writer_proofs_verify_in_the_independent_verifier(items, data):
    leaves = [merkle.leaf_hash(x) for x in items]
    n = len(leaves)
    root = merkle.root_from_leaf_hashes(leaves)
    assert tree.mth(leaves) == tree.mth_large(leaves) == root
    i = data.draw(st.integers(0, n - 1))
    proof = merkle.inclusion_proof(leaves, i)
    assert tree.verify_inclusion(leaves[i], i, n, proof, root)
    assert not tree.verify_inclusion(merkle.leaf_hash(items[i] + b"!"), i, n, proof, root)
    m = data.draw(st.integers(1, n))
    cproof = merkle.consistency_proof(leaves, m)
    old_root = merkle.root_from_leaf_hashes(leaves[:m])
    assert tree.verify_consistency(m, n, old_root, root, cproof)
    assert merkle.verify_consistency(m, n, old_root, root, cproof)
    if m < n:
        assert not tree.verify_consistency(m, n, hashlib.sha256(b"forged").digest(), root, cproof)


@given(st.integers(min_value=0, max_value=3 * 65536 + 999), st.integers(min_value=1, max_value=255))
@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_any_single_byte_change_is_localised(tmp_path_factory, position, xor):
    path = tmp_path_factory.mktemp("flip") / "evidence.bin"
    rnd = random.Random(42)
    data = bytearray(rnd.randbytes(3 * 65536 + 1000))
    path.write_bytes(bytes(data))
    before = hash_file(path, chunk_size=65536, digests=())
    data[position] ^= xor
    path.write_bytes(bytes(data))
    after = hash_file(path, chunk_size=65536, digests=())
    assert before.root != after.root
    changed = [i for i, (a, b) in enumerate(zip(before.leaves, after.leaves)) if a != b]
    assert changed == [position // 65536]


@given(st.dictionaries(st.text(max_size=8), st.one_of(st.integers(-2**53, 2**53), st.text(max_size=20), st.booleans(),
                                                      st.none()), max_size=8))
def test_canonical_json_is_stable_and_strict(value):
    encoded = canonical.dumps(value)
    assert canonical.loads(encoded) == value
    assert canonical.dumps(canonical.loads(encoded)) == encoded


def test_canonical_rejects_floats_and_non_canonical_bytes():
    import pytest

    with pytest.raises(canonical.CanonicalError):
        canonical.dumps({"a": 0.1})
    with pytest.raises(canonical.CanonicalError):
        canonical.loads(b'{"b":1, "a":2}')


@given(st.integers(min_value=0, max_value=400), st.integers(min_value=0, max_value=7))
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_any_bit_flip_in_a_signed_entry_breaks_verification(case_factory, position, bit):
    case = case_factory()
    conn = case.raw()
    body, = conn.execute("SELECT body FROM entries WHERE seq=1").fetchone()
    pos = position % len(body)
    mutated = bytearray(body)
    mutated[pos] ^= 1 << bit
    conn.execute("UPDATE entries SET body=? WHERE seq=1", (bytes(mutated),))
    conn.close()
    report = case.verify()
    assert report["result"] == "fail"


def test_blake3_leaves_round_trip(tmp_path):
    path = tmp_path / "e.bin"
    path.write_bytes(os.urandom(300_000))
    r = hash_file(path, chunk_size=65536, alg="blake3", digests=())
    assert tree.mth_large(r.leaves, tree.h_blake3) == r.root
    assert r.root != hash_file(path, chunk_size=65536, digests=()).root
