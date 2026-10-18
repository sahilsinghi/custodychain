from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest

os.environ.setdefault("CUSTODY_KEY_PASSWORD", "test-password-123")

from custodychain import keys  # noqa: E402
from custodychain.hasher import hash_evidence  # noqa: E402
from custodychain.ledger import Ledger  # noqa: E402
from custodychain.testtsa import TestTSA, serve  # noqa: E402
from custodyverify.check import CaseVerifier  # noqa: E402

MIB = 1 << 20


@pytest.fixture(scope="session")
def lab_tsa(tmp_path_factory):
    d = tmp_path_factory.mktemp("tsa")
    tsa = TestTSA.create("ec")
    tsa.save(d)
    server = serve(tsa, port=0)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    yield tsa, url, d / "ca.pem"
    server.shutdown()


@dataclass
class Case:
    root: Path
    db: Path
    admin: keys.Signer
    alice: keys.Signer
    bob: keys.Signer
    evidence: Path
    tsa_url: str
    ca: Path

    def ledger(self) -> Ledger:
        return Ledger(self.db)

    def verify(self, **kwargs) -> dict:
        kwargs.setdefault("ca_bundles", [self.ca])
        return CaseVerifier(self.db, **kwargs).run()

    def raw(self) -> sqlite3.Connection:
        """What an insider with file access can do: drop the guard triggers and edit."""
        conn = sqlite3.connect(self.db, isolation_level=None)
        conn.execute("DROP TRIGGER IF EXISTS entries_append_only_update")
        conn.execute("DROP TRIGGER IF EXISTS entries_append_only_delete")
        return conn


def check(report: dict, cid: str) -> dict:
    return next(c for c in report["checks"] if c["id"] == cid)


def build_case(tmp_path: Path, url: str, ca: Path) -> Case:
    admin = keys.generate("admin", "admin", tmp_path / "keys" / "admin.key")
    alice = keys.generate("alice", "analyst", tmp_path / "keys" / "alice.key")
    bob = keys.generate("bob", "analyst", tmp_path / "keys" / "bob.key")
    db = tmp_path / "case.db"
    ledger = Ledger.create(db, "CASE-T", "test case", admin, [alice.public, bob.public])
    evidence = tmp_path / "disk.raw"
    evidence.write_bytes(os.urandom(10 * MIB + 12345))
    result = hash_evidence(evidence, chunk_size=MIB, workers=1)
    ledger.record_exhibit(alice, "acquire", "EX-1", "test disk", result)
    ledger.append(alice, "analyze", details={"exhibit": "EX-1", "note": "timeline built"})
    ledger.append(alice, "handover", witness=bob, details={"exhibit": "EX-1", "from": "alice", "to": "bob", "reason": "locker"})
    ledger.anchor(bob, [("lab", url)])
    ledger.append(bob, "note", details={"note": "reviewed"})
    ledger.close()
    return Case(tmp_path, db, admin, alice, bob, evidence, url, ca)


@pytest.fixture()
def case(tmp_path, lab_tsa) -> Case:
    _, url, ca = lab_tsa
    return build_case(tmp_path, url, ca)


@pytest.fixture()
def case_factory(tmp_path_factory, lab_tsa):
    _, url, ca = lab_tsa
    return lambda: build_case(tmp_path_factory.mktemp("case"), url, ca)
