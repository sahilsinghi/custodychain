"""The spec's "test cases that prove it works", one by one."""

from __future__ import annotations

import base64
import json
import sqlite3

from conftest import MIB, check

from custodychain import canonical, keys
from custodychain.ledger import DOMAIN_ENTRY, Ledger, record_bytes


def test_clean_case_verifies(case):
    report = case.verify(evidence={"EX-1": case.evidence})
    assert report["result"] in ("pass", "warn")
    assert all(c["status"] in ("pass", "warn") for c in report["checks"]), report["checks"]
    assert check(report, "exhibit:EX-1")["status"] == "pass"
    assert check(report, "anchors")["status"] in ("pass", "warn")


def test_flipped_byte_names_the_exact_chunk(case):
    data = bytearray(case.evidence.read_bytes())
    offset = 7 * MIB + 4242  # chunk 7 with 1 MiB leaves
    data[offset] ^= 0x01
    case.evidence.write_bytes(bytes(data))
    report = case.verify(evidence={"EX-1": case.evidence})
    c = check(report, "exhibit:EX-1")
    assert c["status"] == "fail"
    assert any(f.startswith("chunk 7 differs: bytes 7340032..8388607") for f in c["findings"]), c["findings"]
    ex = next(e for e in report["exhibits"] if e["id"] == "EX-1")
    assert ex["failing_chunks"] == [7]


def test_truncated_evidence_is_reported(case):
    data = case.evidence.read_bytes()
    case.evidence.write_bytes(data[: 5 * MIB])
    c = check(case.verify(evidence={"EX-1": case.evidence}), "exhibit:EX-1")
    assert c["status"] == "fail"
    assert any("bytes were recorded" in f for f in c["findings"])


def _edit_row(case, seq: int, mutate):
    conn = case.raw()
    body, = conn.execute("SELECT body FROM entries WHERE seq=?", (seq,)).fetchone()
    value = json.loads(body)
    mutate(value)
    conn.execute("UPDATE entries SET body=? WHERE seq=?", (canonical.dumps(value), seq))
    conn.close()


def test_edited_row_breaks_signature_and_chain_at_that_row(case):
    _edit_row(case, 2, lambda b: b["details"].update(note="nothing found"))
    report = case.verify()
    assert any(f.startswith("seq 2: Ed25519 signature") for f in check(report, "signatures")["findings"])
    assert any(f.startswith("seq 3: prev hash does not match") for f in check(report, "chain")["findings"])
    assert report["result"] == "fail"


def test_deleted_row_is_detected(case):
    conn = case.raw()
    conn.execute("DELETE FROM entries WHERE seq=2")
    conn.close()
    findings = check(case.verify(), "chain")["findings"]
    assert any("row 2: stored seq is 3" in f for f in findings)
    assert any("seq 3: prev hash does not match" in f for f in findings)


def test_reordered_rows_are_detected(case):
    conn = case.raw()
    rows = conn.execute("SELECT seq, body, signature, cosignatures, entry_hash FROM entries ORDER BY seq").fetchall()
    conn.execute("DELETE FROM entries")
    order = [0, 1, 3, 2] + list(range(4, len(rows)))
    for new_seq, old in enumerate(order):
        r = rows[old]
        conn.execute("INSERT INTO entries VALUES (?,?,?,?,?)", (new_seq, r[1], r[2], r[3], r[4]))
    conn.close()
    findings = check(case.verify(), "chain")["findings"]
    assert any("seq 2: body says seq 3" in f for f in findings)


def test_entry_signed_by_unknown_key_reports_fingerprint(case, tmp_path):
    mallory = keys.generate("alice", "analyst", tmp_path / "mallory.key")  # impersonates alice
    ledger = case.ledger()
    last = ledger.entries()[-1]
    body = {
        "v": 1, "case": "CASE-T", "seq": last.seq + 1, "prev": last.entry_hash.hex(), "time": "2026-10-18T00:00:00Z",
        "actor": "alice", "key_id": mallory.key_id, "action": "note", "exhibit": None,
        "details": {"note": "planted"}, "witness": None,
    }
    body_bytes = canonical.dumps(body)
    sig = mallory.sign(DOMAIN_ENTRY + body_bytes)
    import hashlib

    eh = hashlib.sha256(record_bytes(body, sig, [])).digest()
    ledger.db.execute("INSERT INTO entries VALUES (?,?,?,?,?)", (body["seq"], body_bytes, sig, "[]", eh))
    findings = check(case.verify(), "signatures")["findings"]
    assert any(f"signed by unknown key {mallory.key_id}" in f for f in findings), findings


def test_truncate_and_reanchor_fails_against_earlier_checkpoint(case, tmp_path):
    ledger = case.ledger()
    ledger.append(case.alice, "note", details={"note": "more work"})
    ledger.anchor(case.bob, [("lab", case.tsa_url)])
    cp = ledger.checkpoint()
    (tmp_path / "cp-v1.json").write_text(json.dumps(cp))
    size_v1 = cp["tree_size"]
    ledger.close()
    # insider removes the last entries (and the anchor rows that mention them) then re-anchors
    conn = case.raw()
    conn.execute("DELETE FROM entries WHERE seq >= ?", (size_v1 - 3,))
    conn.execute("DELETE FROM anchors WHERE tree_size >= ?", (size_v1 - 3,))
    conn.close()
    ledger = Ledger(case.db)
    ledger.anchor(case.bob, [("lab", case.tsa_url)])
    ledger.close()
    report = case.verify(checkpoints=[tmp_path / "cp-v1.json"])
    c = check(report, "checkpoint:cp-v1.json")
    assert c["status"] == "fail"
    assert any("history was rewritten" in f or "truncation" in f for f in c["findings"]), c["findings"]


def test_truncation_detected_from_surviving_anchor_rows(case):
    conn = case.raw()
    conn.execute("DELETE FROM entries WHERE seq >= 3")
    conn.close()
    findings = check(case.verify(), "anchors")["findings"]
    assert any("the log was truncated after it was timestamped" in f for f in findings)


def test_offline_consistency_proof(case, tmp_path):
    from custodyverify.check import verify_consistency_files

    ledger = case.ledger()
    old = ledger.checkpoint()
    ledger.append(case.alice, "note", details={"note": "later"})
    ledger.append(case.bob, "note", details={"note": "later still"})
    new = ledger.checkpoint()
    proof = ledger.consistency(old["tree_size"])
    assert verify_consistency_files(old, new, proof)[0]
    forged = dict(old, root="00" * 32)
    assert not verify_consistency_files(forged, new, proof)[0]


def test_corrupted_token_fails_cleanly(case):
    conn = case.raw()
    token, = conn.execute("SELECT token FROM anchors LIMIT 1").fetchone()
    bad = bytearray(token)
    bad[len(bad) - 40] ^= 0xFF  # inside the signature
    conn.execute("UPDATE anchors SET token=?", (bytes(bad),))
    conn.close()
    c = check(case.verify(), "anchors")
    assert c["status"] == "fail"
    assert any("anchor" in f and ("signature" in f or "malformed" in f or "not referenced" in f) for f in c["findings"])


def test_wrong_ca_bundle_fails_cleanly(case, tmp_path):
    from custodychain.testtsa import TestTSA

    other = TestTSA.create("rsa")
    other.save(tmp_path / "other")
    c = check(case.verify(ca_bundles=[tmp_path / "other" / "ca.pem"]), "anchors")
    assert c["status"] == "fail"
    assert any("no trusted issuer" in f for f in c["findings"])


def test_anchored_root_changed_by_rewriting_history(case):
    _edit_row(case, 1, lambda b: b["exhibit"].update(label="relabelled"))
    findings = check(case.verify(), "anchors")["findings"]
    assert any("no longer hash to the timestamped root" in f for f in findings)


def test_compromised_key_invalidates_later_entries_only(case):
    ledger = case.ledger()
    stolen = ledger.append(case.alice, "note", details={"note": "attacker entry"}).seq
    ledger.revoke_key(case.admin, case.alice.key_id, "compromised", compromised_since_seq=stolen)
    findings = check(case.verify(), "signatures")["findings"]
    assert any(f.startswith(f"seq {stolen}: signed by") and "compromise point" in f for f in findings)
    assert not any(f.startswith("seq 1:") for f in findings)  # alice's acquisition stays valid


def test_revoked_key_cannot_sign_and_non_admin_cannot_manage_keys(case):
    import pytest

    from custodychain.ledger import LedgerError

    ledger = case.ledger()
    ledger.revoke_key(case.admin, case.bob.key_id, "left")
    with pytest.raises(LedgerError):
        ledger.append(case.bob, "note", details={"note": "after leaving"})
    with pytest.raises(LedgerError):
        ledger.add_key(case.alice, keys.PublicKey("eve", "analyst", b"\x01" * 32))


def test_handover_requires_matching_witness_cosignature(case):
    conn = case.raw()
    seq, cos = conn.execute("SELECT seq, cosignatures FROM entries WHERE body LIKE '%\"handover\"%'").fetchone()
    sigs = json.loads(cos)
    sigs[0]["signature"] = "00" * 64
    conn.execute("UPDATE entries SET cosignatures=? WHERE seq=?", (canonical.dumps(sigs).decode(), seq))
    conn.close()
    findings = check(case.verify(), "signatures")["findings"]
    assert any(f"seq {seq}: witness co-signature" in f for f in findings)


def test_future_dated_entry_is_caught_by_tsa_time(case):
    ledger = case.ledger()
    e = ledger.append(case.alice, "note", details={"note": "clock wrong"}, time="2031-01-01T00:00:00Z")
    ledger.anchor(case.bob, [("lab", case.tsa_url)])
    findings = check(case.verify(), "time")["findings"]
    assert any(f.startswith(f"seq {e.seq}: claims 2031") for f in findings)


def test_backdated_entry_is_caught(case):
    ledger = case.ledger()
    e = ledger.append(case.alice, "note", details={"note": "backdated"}, time="2020-01-01T00:00:00Z")
    findings = check(case.verify(), "time")["findings"]
    assert any(f.startswith(f"seq {e.seq}: claims 2020") and "backdated" in f for f in findings)


def test_leaf_cache_tampering_is_detected(case):
    conn = sqlite3.connect(case.db)
    conn.execute("UPDATE exhibit_leaves SET hash=? WHERE exhibit_id='EX-1' AND idx=3", (b"\x00" * 32,))
    conn.commit()
    conn.close()
    c = check(case.verify(), "exhibit:EX-1")
    assert any("leaf table tampered" in f for f in c["findings"])


def test_pinned_genesis(case):
    good = case.ledger().entries()[0].entry_hash.hex()
    assert check(case.verify(expect_genesis=good), "genesis")["status"] == "pass"
    assert check(case.verify(expect_genesis="ab" * 32), "genesis")["status"] == "fail"


def test_verifier_never_modifies_the_case_file(case):
    before = case.db.read_bytes()
    case.verify(evidence={"EX-1": case.evidence})
    assert case.db.read_bytes() == before


def test_writer_refuses_update_and_delete(case):
    import pytest

    conn = sqlite3.connect(case.db)
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE entries SET body=x'00' WHERE seq=1")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM entries WHERE seq=1")
    conn.close()
    assert base64  # keep import used
