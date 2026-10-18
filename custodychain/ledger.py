"""The custody ledger: an append-only, hash-chained, signed log in SQLite.

Every analyst action is an *entry*. Its body is canonical JSON containing the
previous entry's hash, so editing, deleting or reordering any row breaks the
chain from that row on. The body is signed with the acting analyst's Ed25519
key; handovers are also co-signed by the receiving analyst (witness). The
log's Merkle root (RFC 9162, one leaf per entry) is periodically anchored
with RFC 3161 timestamps and the anchor itself is logged as an entry.

Identity is part of the log. The genesis entry (``case_open``) carries the
initial key roster and is signed by the case administrator; later
``key_add`` / ``key_revoke`` entries must be signed by an active admin key.
A revocation can declare ``compromised_since_seq`` so entries signed by a
stolen key after that point are rejected, while earlier work stays valid.

This module has no UPDATE or DELETE statements for entries, and the schema
adds triggers that abort them. Neither is a security boundary - anyone with
the file can drop a trigger - which is why the verifier trusts only the
cryptography.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from custodychain import anchor, canonical
from custodychain.hasher import HashResult
from custodychain.keys import PublicKey, Signer, key_id
from custodychain.merkle import consistency_proof, inclusion_proof, leaf_hash, root_from_leaf_hashes

FORMAT = "custodychain/1"
DOMAIN_ENTRY = b"custodychain/v1/entry\x00"
DOMAIN_WITNESS = b"custodychain/v1/witness\x00"
GENESIS_PREV = "00" * 32

ACTIONS = {
    "case_open", "key_add", "key_revoke", "acquire", "verify", "copy", "mount", "analyze", "export",
    "handover", "note", "anchor", "seal",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entries (
    seq INTEGER PRIMARY KEY,
    body BLOB NOT NULL,
    signature BLOB NOT NULL,
    cosignatures TEXT NOT NULL,
    entry_hash BLOB NOT NULL
);
CREATE TRIGGER IF NOT EXISTS entries_append_only_update BEFORE UPDATE ON entries
BEGIN SELECT RAISE(ABORT, 'custody log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS entries_append_only_delete BEFORE DELETE ON entries
BEGIN SELECT RAISE(ABORT, 'custody log is append-only'); END;
CREATE TABLE IF NOT EXISTS exhibits (
    exhibit_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    chunk_size INTEGER NOT NULL,
    alg TEXT NOT NULL,
    merkle_root BLOB NOT NULL,
    leaf_count INTEGER NOT NULL,
    parent TEXT,
    created_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS exhibit_leaves (
    exhibit_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    hash BLOB NOT NULL,
    PRIMARY KEY (exhibit_id, idx)
);
CREATE TABLE IF NOT EXISTS hash_jobs (
    job_id TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    chunk_size INTEGER NOT NULL,
    alg TEXT NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS job_leaves (
    job_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    hash BLOB NOT NULL,
    PRIMARY KEY (job_id, idx)
);
CREATE TABLE IF NOT EXISTS anchors (
    id INTEGER PRIMARY KEY,
    tree_size INTEGER NOT NULL,
    root BLOB NOT NULL,
    tsa TEXT NOT NULL,
    url TEXT NOT NULL,
    token BLOB NOT NULL,
    gen_time TEXT NOT NULL,
    logged_seq INTEGER
);
"""


class LedgerError(Exception):
    pass


@dataclass
class Entry:
    seq: int
    body: dict[str, Any]
    body_bytes: bytes
    signature: bytes
    cosignatures: list[dict[str, str]]
    entry_hash: bytes

    @property
    def leaf_bytes(self) -> bytes:
        return record_bytes(self.body, self.signature, self.cosignatures)


def record_bytes(body: dict[str, Any], signature: bytes, cosignatures: list[dict[str, str]]) -> bytes:
    """The bytes committed by the chain and the log Merkle tree."""
    return canonical.dumps({"body": body, "signature": signature.hex(), "cosignatures": cosignatures})


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)
        if not self.path.exists():
            raise LedgerError(f"{self.path} does not exist (create it with `custody init`)")
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)

    # -- creation ------------------------------------------------------
    @classmethod
    def create(cls, path: Path, case_id: str, title: str, admin: Signer,
               roster: Iterable[PublicKey] = (), details: dict[str, Any] | None = None) -> "Ledger":
        path = Path(path)
        if path.exists():
            raise LedgerError(f"{path} already exists")
        if admin.role != "admin":
            raise LedgerError("the case must be opened with an admin key")
        sqlite3.connect(path).close()
        ledger = cls(path)
        ledger.db.execute("INSERT INTO meta VALUES ('format', ?), ('case_id', ?)", (FORMAT, case_id))
        members = [admin.public] + [k for k in roster if k.key_id != admin.key_id]
        ledger.append(admin, "case_open", details={
            "title": title,
            "roster": [m.to_json() for m in members],
            **(details or {}),
        })
        return ledger

    def close(self) -> None:
        self.db.close()

    @property
    def case_id(self) -> str:
        row = self.db.execute("SELECT v FROM meta WHERE k='case_id'").fetchone()
        return row[0] if row else ""

    # -- reading -------------------------------------------------------
    def entries(self) -> list[Entry]:
        rows = self.db.execute("SELECT seq, body, signature, cosignatures, entry_hash FROM entries ORDER BY seq").fetchall()
        return [Entry(seq, json.loads(body), body, sig, json.loads(cos), eh) for seq, body, sig, cos, eh in rows]

    def size(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    def last(self) -> Entry | None:
        es = self.db.execute("SELECT seq FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
        return self.entries()[-1] if es else None

    def leaf_hashes(self, size: int | None = None) -> list[bytes]:
        entries = self.entries()
        if size is not None:
            entries = entries[:size]
        return [leaf_hash(e.leaf_bytes) for e in entries]

    def root(self, size: int | None = None) -> bytes:
        return root_from_leaf_hashes(self.leaf_hashes(size))

    def roster(self) -> dict[str, dict[str, Any]]:
        """Replay key_add / key_revoke to get the current roster (writer-side view)."""
        roster: dict[str, dict[str, Any]] = {}
        for e in self.entries():
            d = e.body.get("details") or {}
            if e.body["action"] == "case_open":
                for m in d.get("roster", []):
                    roster[m["key_id"]] = {**m, "active": True}
            elif e.body["action"] == "key_add":
                roster[d["key"]["key_id"]] = {**d["key"], "active": True}
            elif e.body["action"] == "key_revoke" and d.get("key_id") in roster:
                roster[d["key_id"]]["active"] = False
        return roster

    def exhibit(self, exhibit_id: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT exhibit_id,label,kind,size,chunk_size,alg,merkle_root,leaf_count,parent,created_seq FROM exhibits WHERE exhibit_id=?",
            (exhibit_id,),
        ).fetchone()
        if not row:
            return None
        keys = ["exhibit_id", "label", "kind", "size", "chunk_size", "alg", "merkle_root", "leaf_count", "parent", "created_seq"]
        return dict(zip(keys, row))

    def exhibit_leaves(self, exhibit_id: str) -> list[bytes]:
        return [r[0] for r in self.db.execute("SELECT hash FROM exhibit_leaves WHERE exhibit_id=? ORDER BY idx", (exhibit_id,))]

    # -- writing -------------------------------------------------------
    def _authorize(self, signer: Signer, action: str) -> None:
        if action == "case_open":
            return
        roster = self.roster()
        member = roster.get(signer.key_id)
        if member is None or not member["active"]:
            raise LedgerError(f"key {signer.key_id} ({signer.actor}) is not an active member of this case's roster")
        if action in ("key_add", "key_revoke") and member["role"] != "admin":
            raise LedgerError(f"{action} must be signed by an admin key")

    def append(self, signer: Signer, action: str, exhibit: dict[str, Any] | None = None,
               details: dict[str, Any] | None = None, witness: Signer | None = None,
               time: str | None = None) -> Entry:
        if action not in ACTIONS:
            raise LedgerError(f"unknown action {action!r}")
        self._authorize(signer, action)
        if action == "handover" and witness is None:
            raise LedgerError("a handover must be co-signed by the receiving analyst (witness)")
        if witness is not None:
            w = self.roster().get(witness.key_id)
            if w is None or not w["active"]:
                raise LedgerError(f"witness key {witness.key_id} is not active in the roster")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
            seq = 0 if row is None else row[0] + 1
            prev = GENESIS_PREV if row is None else row[1].hex()
            body = {
                "v": 1,
                "case": self.case_id,
                "seq": seq,
                "prev": prev,
                "time": time or utcnow(),
                "actor": signer.actor,
                "key_id": signer.key_id,
                "action": action,
                "exhibit": exhibit,
                "details": details or {},
                "witness": None if witness is None else {"actor": witness.actor, "key_id": witness.key_id},
            }
            body_bytes = canonical.dumps(body)
            signature = signer.sign(DOMAIN_ENTRY + body_bytes)
            cosigs = []
            if witness is not None:
                cosigs.append({"actor": witness.actor, "key_id": witness.key_id,
                               "signature": witness.sign(DOMAIN_WITNESS + body_bytes).hex()})
            rec = record_bytes(body, signature, cosigs)
            entry_hash = hashlib.sha256(rec).digest()
            self.db.execute("INSERT INTO entries VALUES (?,?,?,?,?)",
                            (seq, body_bytes, signature, canonical.dumps(cosigs).decode(), entry_hash))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return Entry(seq, body, body_bytes, signature, cosigs, entry_hash)

    # -- keys ----------------------------------------------------------
    def add_key(self, admin: Signer, key: PublicKey, note: str = "") -> Entry:
        if key.key_id in self.roster():
            raise LedgerError(f"{key.key_id} is already in the roster")
        return self.append(admin, "key_add", details={"key": key.to_json(), "note": note})

    def revoke_key(self, admin: Signer, kid: str, reason: str, compromised_since_seq: int | None = None) -> Entry:
        if kid not in self.roster():
            raise LedgerError(f"{kid} is not in the roster")
        if reason not in ("lost", "compromised", "rotated", "left"):
            raise LedgerError("reason must be lost, compromised, rotated or left")
        return self.append(admin, "key_revoke", details={
            "key_id": kid, "reason": reason, "compromised_since_seq": compromised_since_seq,
        })

    # -- exhibits ------------------------------------------------------
    def exhibit_summary(self, exhibit_id: str, label: str, result: HashResult, parent: str | None = None,
                        source: dict[str, Any] | None = None) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "id": exhibit_id,
            "label": label,
            "kind": result.kind,
            "size": result.size,
            "chunk_size": result.chunk_size,
            "alg": result.alg,
            "leaves": len(result.leaves),
            "merkle_root": result.root.hex(),
            "digests": result.digests,
            "parent": parent,
            "source": source or {},
        }
        if result.ewf:
            summary["ewf"] = {k: v for k, v in result.ewf.items() if k != "libewf"}
            if "libewf" in result.ewf:
                summary["ewf"]["libewf_agrees"] = result.ewf["libewf"].get("agrees")
        return summary

    def record_exhibit(self, signer: Signer, action: str, exhibit_id: str, label: str, result: HashResult,
                       parent: str | None = None, details: dict[str, Any] | None = None,
                       source: dict[str, Any] | None = None) -> Entry:
        if self.exhibit(exhibit_id) is not None:
            raise LedgerError(f"exhibit {exhibit_id} already exists")
        summary = self.exhibit_summary(exhibit_id, label, result, parent, source)
        entry = self.append(signer, action, exhibit=summary, details=details)
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO exhibits VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (exhibit_id, label, result.kind, result.size, result.chunk_size, result.alg, result.root,
                         len(result.leaves), parent, entry.seq))
        self.db.executemany("INSERT INTO exhibit_leaves VALUES (?,?,?)",
                            [(exhibit_id, i, h) for i, h in enumerate(result.leaves)])
        self.db.execute("COMMIT")
        return entry

    # -- resumable hashing --------------------------------------------
    def job_for(self, path: Path, chunk_size: int, alg: str) -> tuple[str, list[bytes]]:
        st = Path(path).stat()
        job_id = hashlib.sha256(f"{Path(path).resolve()}|{st.st_size}|{st.st_mtime_ns}|{chunk_size}|{alg}".encode()).hexdigest()[:24]
        row = self.db.execute("SELECT status FROM hash_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            self.db.execute("INSERT INTO hash_jobs VALUES (?,?,?,?,?,?,?)",
                            (job_id, str(Path(path).resolve()), st.st_size, st.st_mtime_ns, chunk_size, alg, "running"))
            return job_id, []
        leaves = [r[0] for r in self.db.execute("SELECT hash FROM job_leaves WHERE job_id=? ORDER BY idx", (job_id,))]
        return job_id, leaves

    def checkpoint_leaves(self, job_id: str, first: int, leaves: list[bytes]) -> None:
        self.db.execute("BEGIN")
        self.db.executemany("INSERT OR REPLACE INTO job_leaves VALUES (?,?,?)",
                            [(job_id, first + i, h) for i, h in enumerate(leaves)])
        self.db.execute("COMMIT")

    def finish_job(self, job_id: str) -> None:
        self.db.execute("UPDATE hash_jobs SET status='done' WHERE job_id=?", (job_id,))
        self.db.execute("DELETE FROM job_leaves WHERE job_id=?", (job_id,))

    # -- anchoring -----------------------------------------------------
    def anchor(self, signer: Signer, tsas: list[tuple[str, str]], min_ok: int = 1) -> tuple[Entry, list[str]]:
        size = self.size()
        root = self.root(size)
        tokens, errors = [], []
        for name, url in tsas:
            try:
                tokens.append(anchor.request_token(url, root, name))
            except anchor.TimestampError as exc:
                errors.append(f"{name}: {exc}")
        if len(tokens) < min_ok:
            raise LedgerError("no TSA issued a token: " + "; ".join(errors))
        for t in tokens:
            self.db.execute("INSERT INTO anchors (tree_size, root, tsa, url, token, gen_time) VALUES (?,?,?,?,?,?)",
                            (size, root, t.tsa, t.url, t.token, t.gen_time.isoformat()))
        entry = self.append(signer, "anchor", details={
            "tree_size": size,
            "root": root.hex(),
            "tokens": [{**t.summary(), "token_sha256": hashlib.sha256(t.token).hexdigest()} for t in tokens],
            "errors": errors,
        })
        self.db.execute("UPDATE anchors SET logged_seq=? WHERE tree_size=? AND logged_seq IS NULL", (entry.seq, size))
        return entry, errors

    def anchors(self) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT id, tree_size, root, tsa, url, token, gen_time, logged_seq FROM anchors ORDER BY id").fetchall()
        keys = ["id", "tree_size", "root", "tsa", "url", "token", "gen_time", "logged_seq"]
        return [dict(zip(keys, r)) for r in rows]

    # -- proofs and checkpoints ---------------------------------------
    def checkpoint(self) -> dict[str, Any]:
        size = self.size()
        entries = self.entries()
        anchors = [a for a in self.anchors() if a["tree_size"] == size]
        import base64

        return {
            "format": FORMAT,
            "case": self.case_id,
            "genesis": entries[0].entry_hash.hex() if entries else None,
            "tree_size": size,
            "root": self.root(size).hex(),
            "timestamps": [{"tsa": a["tsa"], "gen_time": a["gen_time"], "token": base64.b64encode(a["token"]).decode()}
                           for a in anchors],
        }

    def consistency(self, old_size: int) -> dict[str, Any]:
        leaves = self.leaf_hashes()
        return {
            "old_size": old_size,
            "new_size": len(leaves),
            "old_root": root_from_leaf_hashes(leaves[:old_size]).hex(),
            "new_root": root_from_leaf_hashes(leaves).hex(),
            "proof": [p.hex() for p in consistency_proof(leaves, old_size)],
        }

    def entry_inclusion(self, seq: int, size: int | None = None) -> dict[str, Any]:
        leaves = self.leaf_hashes(size)
        e = self.entries()[seq]
        return {
            "seq": seq,
            "tree_size": len(leaves),
            "root": root_from_leaf_hashes(leaves).hex(),
            "record": e.leaf_bytes.decode(),
            "proof": [p.hex() for p in inclusion_proof(leaves, seq)],
        }

    def chunk_inclusion(self, exhibit_id: str, index: int) -> dict[str, Any]:
        info = self.exhibit(exhibit_id)
        if info is None:
            raise LedgerError(f"no exhibit {exhibit_id}")
        from custodychain.merkle import HASHES

        h = HASHES[info["alg"]]
        leaves = self.exhibit_leaves(exhibit_id)
        return {
            "exhibit": exhibit_id,
            "alg": info["alg"],
            "chunk": index,
            "chunk_size": info["chunk_size"],
            "offset": index * info["chunk_size"],
            "leaf_hash": leaves[index].hex(),
            "tree_size": len(leaves),
            "root": info["merkle_root"].hex(),
            "proof": [p.hex() for p in inclusion_proof(leaves, index, h)],
        }


def genesis_fingerprint(entries: list[Entry]) -> str:
    return entries[0].entry_hash.hex() if entries else ""


__all__ = ["Ledger", "LedgerError", "Entry", "key_id"]
