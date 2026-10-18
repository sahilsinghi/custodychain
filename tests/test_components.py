"""Crypto primitives, TSA tokens, E01 handling, resumable hashing."""

from __future__ import annotations

import hashlib
import os

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from custodychain import anchor, ewf
from custodychain.hasher import EvidenceChanged, hash_e01, hash_file
from custodychain.testtsa import TestTSA
from custodyverify import ewfmedia, sigs, tsp, x509


# ---------------------------------------------------------------- signatures
def test_ed25519_matches_cryptography():
    for i in range(10):
        k = ed25519.Ed25519PrivateKey.generate()
        msg = os.urandom(i * 13)
        pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sig = k.sign(msg)
        assert sigs.ed25519_verify(pub, msg, sig)
        assert not sigs.ed25519_verify(pub, msg + b"x", sig)
        assert not sigs.ed25519_verify(pub, msg, sig[:63] + bytes([sig[63] ^ 1]))


def test_rfc8032_test_vector_1():
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert sigs.ed25519_verify(pub, b"", sig)


@pytest.mark.parametrize("hash_name,algo", [("sha256", hashes.SHA256()), ("sha384", hashes.SHA384()), ("sha512", hashes.SHA512())])
def test_rsa_pkcs1_and_pss(hash_name, algo):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = k.public_key().public_numbers().n
    msg = os.urandom(40)
    assert sigs.rsa_pkcs1v15_verify(n, 65537, msg, k.sign(msg, padding.PKCS1v15(), algo), hash_name)
    pss = k.sign(msg, padding.PSS(mgf=padding.MGF1(algo), salt_length=algo.digest_size), algo)
    assert sigs.rsa_pss_verify(n, 65537, msg, pss, hash_name, algo.digest_size)
    assert not sigs.rsa_pss_verify(n, 65537, msg + b"1", pss, hash_name, algo.digest_size)


@pytest.mark.parametrize("oid,curve", [("1.2.840.10045.3.1.7", ec.SECP256R1()), ("1.3.132.0.34", ec.SECP384R1()),
                                       ("1.3.132.0.35", ec.SECP521R1())])
def test_ecdsa_curves(oid, curve):
    c = sigs.CURVES[oid]
    assert sigs._to_affine(sigs._jac_mul(c.n, (c.g[0], c.g[1], 1), c), c) is None  # n*G = O
    k = ec.generate_private_key(curve)
    point = sigs.ec_point(c, k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    msg = os.urandom(30)
    r, s = utils.decode_dss_signature(k.sign(msg, ec.ECDSA(hashes.SHA512())))
    assert sigs.ecdsa_verify(c, point, msg, r, s, "sha512")
    assert not sigs.ecdsa_verify(c, point, msg, r, (s + 1) % c.n, "sha512")


# ---------------------------------------------------------------- RFC 3161
@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_local_tsa_tokens_verify_and_bind_the_digest(tmp_path, kind):
    t = TestTSA.create(kind)
    t.save(tmp_path)
    digest = hashlib.sha256(b"root").digest()
    token = anchor.parse_response(t.respond(anchor.build_request(digest, 99)))
    gen_time, serial, nonce, _ = anchor.check_token(token, digest, 99)
    assert nonce == 99
    anchors = x509.load_pem_bundle(tmp_path / "ca.pem")
    res = tsp.verify_token(token, digest, anchors)
    assert res.ok, res.problems
    assert res.gen_time == gen_time
    assert not tsp.verify_token(token, hashlib.sha256(b"other").digest(), anchors).ok
    with pytest.raises(anchor.TimestampError):
        anchor.check_token(token, digest, 100)  # nonce replay check


def test_tsa_refusal_is_reported():
    from custodychain import der

    refused = der.seq(der.seq(der.integer(2), der.seq(der.utf8("bad request"))))
    with pytest.raises(anchor.TimestampError, match="bad request"):
        anchor.parse_response(refused)


# ---------------------------------------------------------------- E01
@pytest.mark.parametrize("compress", [True, False])
def test_e01_media_hash_and_embedded_hashes(tmp_path, compress):
    raw = tmp_path / "disk.raw"
    data = os.urandom(200_000) + b"\x00" * (1 << 20) + os.urandom(48_000)
    raw.write_bytes(data[: len(data) // 512 * 512])
    e01 = tmp_path / "disk.E01"
    stored = ewf.write_e01(raw, e01, ewf.EwfMetadata(case_number="C1", examiner="t"), compress=compress)
    r = hash_e01(e01, chunk_size=65536)
    plain = hash_file(raw, chunk_size=65536)
    assert r.root == plain.root  # E01 is hashed as media, same tree as the raw image
    assert r.ewf["md5_match"] and r.ewf["sha1_match"]
    assert stored["md5"] == plain.digests["md5"]
    assert b"".join(ewfmedia.media_blocks(e01, 65536)) == raw.read_bytes()
    cross = ewf.libewf_cross_check(e01)
    if cross is not None and "md5" in cross:
        assert cross["md5"] == plain.digests["md5"]


def test_damaged_e01_chunk_is_detected(tmp_path):
    raw = tmp_path / "d.raw"
    raw.write_bytes(os.urandom(64 * 1024))
    e01 = tmp_path / "d.E01"
    ewf.write_e01(raw, e01, compress=False)
    data = bytearray(e01.read_bytes())
    image = ewf.open_e01(e01)
    _, off, _, _ = image.chunks[0]
    data[off + 100] ^= 0xFF
    e01.write_bytes(bytes(data))
    with pytest.raises(ewfmedia.E01Error):
        b"".join(ewfmedia.media_blocks(e01, 65536))


# ---------------------------------------------------------------- hashing
def test_parallel_matches_single_process(tmp_path):
    p = tmp_path / "e.bin"
    p.write_bytes(os.urandom(5 * 65536 * 16 + 777))
    one = hash_file(p, chunk_size=65536, workers=1)
    many = hash_file(p, chunk_size=65536, workers=4)
    assert one.root == many.root and one.digests == many.digests
    assert one.digests["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()


def test_crash_and_resume_gives_the_same_root(tmp_path):
    p = tmp_path / "e.bin"
    p.write_bytes(os.urandom(40 * 65536))
    saved: list[bytes] = []

    class Crash(Exception):
        pass

    def checkpoint(first, leaves):
        saved.extend(leaves)
        if len(saved) >= 16:
            raise Crash

    with pytest.raises(Crash):
        hash_file(p, chunk_size=65536, on_leaves=checkpoint)
    resumed = hash_file(p, chunk_size=65536, existing_leaves=saved)
    assert resumed.resumed_from == 16
    assert resumed.root == hash_file(p, chunk_size=65536).root


def test_resume_through_the_ledger(case_factory, tmp_path):
    from custodychain.ledger import Ledger

    case = case_factory()
    led = Ledger(case.db)
    p = tmp_path / "big.bin"
    p.write_bytes(os.urandom(48 * 65536))
    job, done = led.job_for(p, 65536, "sha256")
    assert done == []
    partial = hash_file(p, chunk_size=65536)
    led.checkpoint_leaves(job, 0, partial.leaves[:20])
    job2, done2 = led.job_for(p, 65536, "sha256")
    assert job2 == job and done2 == partial.leaves[:20]


def test_changing_evidence_during_hashing_is_refused(tmp_path):
    p = tmp_path / "e.bin"
    p.write_bytes(os.urandom(8 * 65536))

    def tamper(first, leaves):
        if first == 0:
            with open(p, "ab") as fh:
                fh.write(b"x")

    with pytest.raises(EvidenceChanged):
        hash_file(p, chunk_size=65536, on_leaves=tamper)
