"""Hostile inputs to the writer and the verifier: they must fail cleanly and quickly, never hang."""

from __future__ import annotations

import json
import os
import struct
import zlib
from pathlib import Path

import pytest

from custodychain import ewf
from custodychain.canonical import dumps as canonical
from custodychain.ledger import Ledger
from custodyverify import ewfmedia
from custodyverify.check import CaseVerifier

from conftest import check


def _sections(data: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 13
    while True:
        kind = data[pos:pos + 16].split(b"\0", 1)[0]
        out.append((pos, kind))
        nxt = struct.unpack("<Q", data[pos + 16:pos + 24])[0]
        if kind == b"done":
            return out
        pos = nxt


def _patch_descriptor(data: bytearray, pos: int, next_offset: int) -> None:
    d = bytearray(data[pos:pos + 76])
    d[16:24] = struct.pack("<Q", next_offset)
    d[72:76] = struct.pack("<I", zlib.adler32(bytes(d[:72])) & 0xFFFFFFFF)
    data[pos:pos + 76] = d


@pytest.fixture()
def e01(tmp_path) -> Path:
    raw = tmp_path / "media.raw"
    raw.write_bytes(os.urandom(512 * 300) + b"\0" * (512 * 700))
    ewf.write_e01(raw, tmp_path / "image.E01")
    return tmp_path / "image.E01"


def test_section_chain_pointing_backwards_is_refused(e01, tmp_path):
    data = bytearray(e01.read_bytes())
    secs = _sections(bytes(data))
    _patch_descriptor(data, secs[-2][0], 13)  # the section before "done" now loops back to the start
    bad = tmp_path / "loop.E01"
    bad.write_bytes(bytes(data))
    with pytest.raises(ewfmedia.E01Error, match="must move forward"):
        ewfmedia.read_layout(bad)
    with pytest.raises(ewf.EwfError, match="must move forward"):
        ewf.open_e01(bad)


def test_chunk_inflating_beyond_the_chunk_size_is_refused(e01, tmp_path):
    data = bytearray(e01.read_bytes())
    vol = next(pos for pos, kind in _sections(bytes(data)) if kind in (b"volume", b"disk"))
    struct.pack_into("<I", data, vol + 76 + 8, 1)  # one sector per chunk: real chunks now "inflate" 64x too far
    bad = tmp_path / "bomb.E01"
    bad.write_bytes(bytes(data))
    with pytest.raises(ewfmedia.E01Error, match="inflates beyond"):
        list(ewfmedia.media_blocks(bad, 1 << 20))
    with pytest.raises(ewf.EwfError, match="inflates beyond"):
        list(ewf.open_e01(bad).iter_media(1 << 20))


def test_inflate_limit_stops_a_real_bomb():
    bomb = zlib.compress(b"\0" * (64 << 20), 9)  # 64 MiB of zeros in ~64 KiB
    assert len(bomb) < 100_000
    with pytest.raises(ewfmedia.E01Error, match="inflates beyond"):
        ewfmedia._inflate(bomb, 32 << 10, "test chunk")
    with pytest.raises(ewf.EwfError, match="inflates beyond"):
        ewf._inflate(bomb, 32 << 10, "test chunk")


def test_damaged_e01_is_reported_on_the_exhibit(case, tmp_path, e01):
    data = bytearray(e01.read_bytes())
    _patch_descriptor(data, _sections(bytes(data))[-2][0], 13)
    bad = tmp_path / "loop.E01"
    bad.write_bytes(bytes(data))
    report = case.verify(evidence={"EX-1": bad})
    c = check(report, "exhibit:EX-1")
    assert c["status"] == "fail" and any("E01 container is damaged" in f for f in c["findings"])


def test_forged_revocation_cannot_blame_genuine_entries(case):
    conn = case.raw()
    n = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    body = {"seq": n, "prev": "00" * 32, "time": "2026-01-01T00:00:00+00:00", "actor": "admin",
            "key_id": case.admin.key_id, "action": "key_revoke",
            "details": {"key_id": case.alice.key_id, "reason": "forged", "compromised_since_seq": 1}}
    raw = canonical(body)
    conn.execute("INSERT INTO entries (seq, body, signature, cosignatures, entry_hash) VALUES (?, ?, ?, ?, ?)",
                 (n, raw, os.urandom(64), "[]", os.urandom(32)))
    conn.close()
    report = case.verify()
    sig = check(report, "signatures")
    assert sig["status"] == "fail"
    assert any(f"seq {n}:" in f for f in sig["findings"])  # the forged row itself is reported
    assert not any("compromise" in f for f in sig["findings"])  # ...and cannot discredit alice's real entries
    alice_entries = [e for e in report["entries"] if e.get("actor") == "alice"]
    assert alice_entries and all(e["signature"] == "valid" for e in alice_entries)


def test_absurd_recorded_chunk_size_is_refused(case):
    conn = case.raw()
    seq, body = next((s, json.loads(b)) for s, b in conn.execute("SELECT seq, body FROM entries")
                     if json.loads(b).get("action") == "acquire")
    body["exhibit"]["chunk_size"] = -1  # read(-1) would pull the whole evidence file into memory
    conn.execute("UPDATE entries SET body = ? WHERE seq = ?", (canonical(body), seq))
    conn.close()
    report = case.verify(evidence={"EX-1": case.evidence})
    c = check(report, "exhibit:EX-1")
    assert c["status"] == "fail" and any("refusing to re-hash" in f for f in c["findings"])


def test_verifier_reads_a_case_while_the_writer_holds_it_open(case):
    led = Ledger(case.db)
    led.append(case.alice, "note", details={"note": "still writing"})
    try:  # the writer's connection (and its WAL) is still open while the verifier runs
        report = case.verify()
    finally:
        led.close()
    assert not any(c["id"].startswith("error:") for c in report["checks"])
    assert check(report, "chain")["status"] == "pass"
    assert report["entries"][-1]["summary"] == "still writing"


def test_tsa_client_only_speaks_http():
    from custodychain.anchor import TimestampError, request_token

    with pytest.raises(TimestampError, match="must be http"):
        request_token("file:///etc/passwd", b"\0" * 32)
