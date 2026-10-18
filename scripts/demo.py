#!/usr/bin/env python3
"""Build a synthetic case end to end, verify it, then tamper with it.

    python scripts/demo.py --out demo-case [--tsa real|local] [--report docs/sample-verification-report.pdf]

Everything is synthetic: random disk images, invented exhibit labels, demo
keys protected by a demo password. Nothing here is case data.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CUSTODY_KEY_PASSWORD", "demo-password-not-secret")

from custodychain import anchor, ewf, keys  # noqa: E402
from custodychain.hasher import hash_evidence  # noqa: E402
from custodychain.ledger import Ledger  # noqa: E402
from custodychain.report import render_pdf  # noqa: E402
from custodychain.testtsa import TestTSA, serve  # noqa: E402
from custodyverify.check import CaseVerifier  # noqa: E402
from custodyverify.cli import print_report  # noqa: E402

MIB = 1 << 20


def synthetic_disk(path: Path, size_mib: int, seed: int) -> None:
    rnd = random.Random(seed)
    with open(path, "wb") as fh:
        for i in range(size_mib):
            if i % 5 == 0:
                fh.write(b"\x00" * MIB)  # unallocated space compresses in the E01
            else:
                fh.write(rnd.randbytes(MIB))


def say(msg: str) -> None:
    print(f"\033[1m==> {msg}\033[0m" if sys.stdout.isatty() else f"==> {msg}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "demo-case")
    ap.add_argument("--tsa", choices=["real", "local"], default="real")
    ap.add_argument("--report", type=Path, help="write the clean verification PDF here")
    ap.add_argument("--tamper-report", type=Path, help="write the tampered-case PDF here")
    args = ap.parse_args()
    os.chdir(ROOT)  # keep paths in the report relative to the repository
    out = args.out if args.out.is_absolute() else ROOT / args.out
    out = Path(os.path.relpath(out, ROOT))
    if out.exists():
        shutil.rmtree(out)
    (out / "keys").mkdir(parents=True)
    (out / "evidence").mkdir()

    lab = TestTSA.create("ec", name="CustodyChain Demo Lab TSA")
    lab.save(out / "lab-tsa")
    server = serve(lab, port=0)
    lab_url = f"http://127.0.0.1:{server.server_address[1]}/"
    tsas = [("lab-tsa", lab_url)]
    if args.tsa == "real":
        tsas = [("freetsa", anchor.PUBLIC_TSAS["freetsa"]), ("digicert", anchor.PUBLIC_TSAS["digicert"])] + tsas

    say("keys: one case admin, three analysts")
    admin = keys.generate("case.admin", "admin", out / "keys" / "case.admin.key")
    alice = keys.generate("alice", "analyst", out / "keys" / "alice.key")
    bob = keys.generate("bob", "analyst", out / "keys" / "bob.key")
    carol = keys.generate("carol", "analyst", out / "keys" / "carol.key")

    say("open the case (genesis entry carries the key roster)")
    db = out / "case.db"
    led = Ledger.create(db, "CASE-2026-0418", "Synthetic insider data-theft investigation", admin,
                        [alice.public, bob.public], details={"lab": "CustodyChain demo lab", "synthetic": True})
    genesis = led.entries()[0].entry_hash.hex()
    print(f"    genesis {genesis}")

    say("acquire EX-001 (laptop SSD as E01) and EX-002 (USB stick, raw)")
    raw1 = out / "evidence" / "laptop.raw"
    synthetic_disk(raw1, 48, 1)
    e01 = out / "evidence" / "EX-001.E01"
    ewf.write_e01(raw1, e01, ewf.EwfMetadata(case_number="CASE-2026-0418", evidence_number="EX-001",
                                            description="Synthetic laptop SSD", examiner="alice"))
    raw1.unlink()
    usb = out / "evidence" / "EX-002.raw"
    synthetic_disk(usb, 24, 2)
    for p in (e01, usb):
        p.chmod(0o444)
    r1 = hash_evidence(e01, chunk_size=4 * MIB)
    led.record_exhibit(alice, "acquire", "EX-001", "Laptop SSD, imaged to E01", r1,
                       source={"file": e01.name, "device": "Synthetic 48 MiB SSD, S/N LAB-0001 (write-blocked)"},
                       details={"tool": "custodychain ewf writer", "write_blocker": "simulated"})
    r2 = hash_evidence(usb, chunk_size=4 * MIB, workers=2)
    led.record_exhibit(alice, "acquire", "EX-002", "USB stick found in desk drawer", r2,
                       source={"file": usb.name, "device": "Synthetic 24 MiB USB stick, S/N LAB-0002"})
    print(f"    EX-001 media root {r1.root.hex()[:24]}…  E01 MD5 match: {r1.ewf['md5_match']}")
    print(f"    EX-002 root {r2.root.hex()[:24]}…")

    say(f"anchor the log root ({', '.join(n for n, _ in tsas)})")
    e, errs = led.anchor(alice, tsas)
    for t in e.body["details"]["tokens"]:
        print(f"    {t['tsa']:9s} {t['gen_time']}")
    for err in errs:
        print(f"    (skipped) {err}")

    say("working copy, mount, analysis, export")
    copy = out / "evidence" / "EX-001-working.E01"
    shutil.copy(e01, copy)
    rc = hash_evidence(copy, chunk_size=4 * MIB)
    assert rc.root == r1.root
    led.record_exhibit(alice, "copy", "EX-001-C1", "Working copy of EX-001", rc, parent="EX-001", source={"file": copy.name})
    led.append(alice, "mount", details={"exhibit": "EX-001-C1", "note": "mounted read-only (ro,noexec)"})
    led.append(alice, "analyze", details={"exhibit": "EX-001-C1", "note": "browser history and LNK files parsed"})
    artefact = out / "evidence" / "exfil-file-list.csv"
    artefact.write_text("path,size,copied_to\n/Users/x/Projects/roadmap.pdf,182044,E:\\\n/Users/x/Finance/q3.xlsx,90211,E:\\\n")
    ra = hash_evidence(artefact, chunk_size=4 * MIB)
    led.record_exhibit(alice, "export", "EX-001-A1", "List of files copied to removable media", ra, parent="EX-001",
                       source={"file": artefact.name})

    say("handover alice -> bob (both sign); bob re-verifies; admin adds carol")
    led.append(alice, "handover", witness=bob, details={"exhibit": "EX-001", "from": "alice", "to": "bob",
                                                        "reason": "peer review"})
    led.append(bob, "verify", details={"exhibit": "EX-001", "note": "re-hashed EX-001: root matches"})
    led.add_key(admin, carol.public, note="court liaison")
    led.append(bob, "handover", witness=carol, details={"exhibit": "EX-001", "from": "bob", "to": "carol",
                                                        "reason": "release to court liaison"})
    cp1 = led.checkpoint()
    led.anchor(bob, tsas)
    led.append(carol, "seal", details={"exhibit": "EX-001", "note": "sealed in bag 7781 for court"})
    led.anchor(carol, tsas)
    (out / "checkpoint-v1.json").write_text(json.dumps(cp1, indent=2))
    proof = led.consistency(cp1["tree_size"])
    (out / "consistency-v1-to-now.json").write_text(json.dumps(proof, indent=2))
    led.close()

    trust = [Path("trust"), out / "lab-tsa" / "ca.pem"]
    evidence = {"EX-001": e01, "EX-002": usb, "EX-001-C1": copy, "EX-001-A1": artefact}
    say("independent verification")
    report = CaseVerifier(db, evidence, trust, genesis, [out / "checkpoint-v1.json"]).run()
    print_report(report)
    (out / "verification.json").write_text(json.dumps(report, indent=2))
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        from custodychain.bsa63 import annex_flowables

        render_pdf(report, args.report, "Synthetic insider data-theft investigation",
                   annex=annex_flowables(Ledger(db), report))
        print(f"    PDF -> {args.report}")

    say("now an insider tampers: rewrites an analysis note, flips one byte of the USB image")
    tampered = out / "tampered"
    tampered.mkdir()
    shutil.copy(db, tampered / "case.db")
    for suffix in ("-wal", "-shm"):
        if Path(str(db) + suffix).exists():
            shutil.copy(Path(str(db) + suffix), tampered / ("case.db" + suffix))
    conn = sqlite3.connect(tampered / "case.db", isolation_level=None)
    conn.execute("DROP TRIGGER entries_append_only_update")  # what an insider with file access can do
    seq, body = conn.execute("SELECT seq, body FROM entries WHERE body LIKE '%LNK files parsed%'").fetchone()
    conn.execute("UPDATE entries SET body=? WHERE seq=?",
                 (body.replace(b"browser history and LNK files parsed", b"nothing of interest found"), seq))
    conn.close()
    print(f"    edited entry {seq} directly in SQLite")
    bad_usb = tampered / "EX-002.raw"
    shutil.copy(usb, bad_usb)
    bad_usb.chmod(0o644)
    offset = 13 * MIB + 4321
    with open(bad_usb, "r+b") as fh:
        fh.seek(offset)
        b = fh.read(1)
        fh.seek(offset)
        fh.write(bytes([b[0] ^ 0x01]))
    print(f"    flipped one bit at byte {offset:,} of EX-002 (4 MiB chunk {offset // (4 * MIB)})")
    report2 = CaseVerifier(tampered / "case.db", {"EX-001": e01, "EX-002": bad_usb}, trust, genesis).run()
    print_report(report2)
    if args.tamper_report:
        render_pdf(report2, args.tamper_report, "Synthetic case - tampered copy")
        print(f"    PDF -> {args.tamper_report}")
    server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
