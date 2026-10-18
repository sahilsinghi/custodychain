"""``custody-verify``: independent verification from the command line (stdlib only).

    custody-verify case.db --tsa-ca trust/ --evidence EX-001=disk.E01 --expect-genesis 3fa1...
    custody-verify consistency checkpoint-v1.json checkpoint-v2.json proof.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from custodyverify import __version__
from custodyverify.check import CaseVerifier, verify_consistency_files

SYMBOL = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "skip": "SKIP"}


def _evidence(pairs: list[str]) -> dict[str, Path]:
    out = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"--evidence expects EXHIBIT_ID=PATH, got {pair!r}")
        k, v = pair.split("=", 1)
        out[k] = Path(v)
    return out


def print_report(report: dict, out=sys.stdout) -> None:
    db = report["database"]
    print(f"custodyverify {report['version']} · case {db.get('case_id')} · {report['log_size']} entries", file=out)
    print(f"genesis {report['genesis']}", file=out)
    print(f"log root {report['log_root']}", file=out)
    print("", file=out)
    for c in report["checks"]:
        print(f"[{SYMBOL[c['status']]}] {c['title']}" + (f" — {c['detail']}" if c['detail'] else ""), file=out)
        for f in c["findings"][:25]:
            print(f"        {f}", file=out)
        if len(c["findings"]) > 25:
            print(f"        ... {len(c['findings']) - 25} more", file=out)
    print("", file=out)
    print(f"RESULT: {report['result'].upper()}", file=out)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "consistency":
        p = argparse.ArgumentParser(prog="custody-verify consistency")
        p.add_argument("old")
        p.add_argument("new")
        p.add_argument("proof")
        a = p.parse_args(argv[1:])
        ok, msg = verify_consistency_files(*(json.loads(Path(x).read_text()) for x in (a.old, a.new, a.proof)))
        print(msg)
        return 0 if ok else 1
    p = argparse.ArgumentParser(prog="custody-verify", description="Independently verify a CustodyChain case.")
    p.add_argument("--version", action="version", version=f"custodyverify {__version__}")
    p.add_argument("database")
    p.add_argument("--evidence", action="append", default=[], metavar="ID=PATH", help="re-hash this evidence file")
    p.add_argument("--tsa-ca", action="append", default=[], help="PEM file or directory of trusted TSA roots")
    p.add_argument("--expect-genesis", help="genesis entry hash from the case paperwork")
    p.add_argument("--checkpoint", action="append", default=[], help="earlier exported checkpoint (append-only check)")
    p.add_argument("--json", help="write the full machine-readable report here")
    p.add_argument("--strict", action="store_true", help="treat warnings as failures")
    a = p.parse_args(argv)
    report = CaseVerifier(Path(a.database), _evidence(a.evidence), [Path(x) for x in a.tsa_ca],
                          a.expect_genesis, [Path(x) for x in a.checkpoint]).run()
    print_report(report)
    if a.json:
        Path(a.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["result"] == "fail" or (a.strict and report["result"] == "warn"):
        return 1
    return 0
