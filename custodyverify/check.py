"""Verify a CustodyChain case database end to end. Read-only, standard library only.

Checks, in order:

1. **chain**      - rows are contiguous from 0, every body is canonical JSON,
                    its ``seq`` matches its row, and ``prev`` equals the hash of
                    the previous record (catches edits, deletes, reordering)
2. **signatures** - every entry verifies against a key that the roster says
                    was active at that point; key changes are admin-signed;
                    handovers carry a valid witness co-signature
3. **genesis**    - optional pin of the case's first entry hash
4. **exhibits**   - stored leaf hashes reproduce the signed Merkle roots; copies
                    match their parent; supplied evidence files are re-hashed
                    and every differing 4 MiB chunk is named
5. **anchors**    - each anchored root is recomputed from the entries, each
                    RFC 3161 token is verified against the chosen CA bundle,
                    and token times are monotonic
6. **time**       - every entry gets a provable window from the timestamps
                    around it; claimed times outside it are flagged
7. **checkpoints**- earlier exported checkpoints must be prefixes of this log
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from custodyverify import __version__, ewfmedia, sigs, tree, tsp

DOMAIN_ENTRY = b"custodychain/v1/entry\x00"
DOMAIN_WITNESS = b"custodychain/v1/witness\x00"
ZERO = "00" * 32
TIME_TOLERANCE = timedelta(minutes=5)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def unhex(value: Any) -> bytes | None:
    try:
        return bytes.fromhex(value) if isinstance(value, str) else None
    except ValueError:
        return None


def key_fingerprint(raw: bytes) -> str:
    return "ed25519:" + hashlib.sha256(raw).digest()[:16].hex()


def parse_time(text: str) -> datetime | None:
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


@dataclass
class Check:
    id: str
    title: str
    status: str = "pass"  # pass | fail | warn | skip
    detail: str = ""
    findings: list[str] = field(default_factory=list)

    def fail(self, msg: str) -> None:
        self.status = "fail"
        self.findings.append(msg)

    def warn(self, msg: str) -> None:
        if self.status == "pass":
            self.status = "warn"
        self.findings.append(msg)

    def to_json(self) -> dict:
        return {"id": self.id, "title": self.title, "status": self.status, "detail": self.detail,
                "findings": self.findings}


@dataclass
class Row:
    seq: int
    body_bytes: bytes
    signature: bytes
    cosignatures_text: str
    stored_hash: bytes
    body: dict | None = None
    record_hash: bytes | None = None
    leaf: bytes | None = None


class CaseVerifier:
    def __init__(self, db: Path, evidence: dict[str, Path] | None = None, ca_bundles: list[Path] | None = None,
                 expect_genesis: str | None = None, checkpoints: list[Path] | None = None):
        self.db_path = Path(db)
        self.evidence = {k: Path(v) for k, v in (evidence or {}).items()}
        self.ca_bundles = [Path(p) for p in (ca_bundles or [])]
        self.expect_genesis = expect_genesis
        self.checkpoint_paths = [Path(p) for p in (checkpoints or [])]
        self.checks: list[Check] = []
        self.rows: list[Row] = []
        self.entries_out: list[dict] = []
        self.exhibits_out: list[dict] = []
        self.anchors_out: list[dict] = []
        self.roster_out: list[dict] = []

    # ------------------------------------------------------------------
    def _snapshot(self) -> tuple[sqlite3.Connection, dict[str, str], Path]:
        """Work on a copy so verification can never modify the case file."""
        tmp = Path(tempfile.mkdtemp(prefix="custody-verify-"))
        hashes = {}
        for suffix in ("", "-wal", "-shm"):
            src = Path(str(self.db_path) + suffix)
            if src.exists():
                shutil.copy2(src, tmp / (self.db_path.name + suffix))
                hashes[src.name] = hashlib.sha256(src.read_bytes()).hexdigest()
        conn = sqlite3.connect(tmp / self.db_path.name)
        return conn, hashes, tmp

    def run(self) -> dict:
        if not self.db_path.exists():
            raise FileNotFoundError(self.db_path)
        conn, file_hashes, tmp = self._snapshot()
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            meta = dict(conn.execute("SELECT k, v FROM meta").fetchall())
            raw_rows = conn.execute("SELECT seq, body, signature, cosignatures, entry_hash FROM entries ORDER BY rowid").fetchall()
            self.rows = [Row(r[0], bytes(r[1]), bytes(r[2]), r[3], bytes(r[4])) for r in raw_rows]
            exhibit_rows = conn.execute("SELECT exhibit_id, alg, merkle_root, leaf_count FROM exhibits").fetchall()
            leaves = {}
            for ex_id, *_ in exhibit_rows:
                leaves[ex_id] = [bytes(r[0]) for r in conn.execute(
                    "SELECT hash FROM exhibit_leaves WHERE exhibit_id=? ORDER BY idx", (ex_id,))]
            anchor_rows = conn.execute("SELECT id, tree_size, root, tsa, url, token, gen_time FROM anchors ORDER BY id").fetchall()
        finally:
            conn.close()
            shutil.rmtree(tmp, ignore_errors=True)

        roster: list[dict] = []
        anchor_times: list = []

        def guarded(name: str, fn, *args):
            # Malformed input must produce a failed check, never a crash.
            try:
                return fn(*args)
            except Exception as exc:  # noqa: BLE001
                c = Check(f"error:{name}", f"{name} could not be evaluated", status="fail",
                          detail=f"{type(exc).__name__}: {exc}")
                self.checks.append(c)
                return None

        guarded("chain", self._check_chain)
        roster = guarded("signatures", self._check_signatures) or []
        guarded("genesis", self._check_genesis)
        guarded("exhibits", self._check_exhibits, exhibit_rows, leaves)
        anchor_times = guarded("anchors", self._check_anchors, anchor_rows) or []
        guarded("time", self._check_time, anchor_times)
        guarded("checkpoints", self._check_checkpoints)

        overall = "fail" if any(c.status == "fail" for c in self.checks) else (
            "warn" if any(c.status == "warn" for c in self.checks) else "pass")
        return {
            "verifier": "custodyverify",
            "version": __version__,
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "database": {"path": str(self.db_path), "sha256": file_hashes, "sqlite_integrity": integrity,
                         "format": meta.get("format"), "case_id": meta.get("case_id")},
            "result": overall,
            "genesis": self.rows[0].record_hash.hex() if self.rows and self.rows[0].record_hash else None,
            "log_size": len(self.rows),
            "log_root": tree.mth_large([r.leaf for r in self.rows if r.leaf]).hex() if self.rows else None,
            "checks": [c.to_json() for c in self.checks],
            "entries": self.entries_out,
            "exhibits": self.exhibits_out,
            "anchors": self.anchors_out,
            "roster": roster,
            "trust": {"ca_bundles": [str(p) for p in self.ca_bundles]},
        }

    # ------------------------------------------------------------------
    def _check_chain(self) -> None:
        c = Check("chain", "Hash chain, ordering and completeness")
        prev_hash = ZERO
        for position, row in enumerate(self.rows):
            if row.seq != position:
                c.fail(f"row {position}: stored seq is {row.seq}; entries are missing, inserted or renumbered here")
            try:
                body = json.loads(row.body_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                c.fail(f"seq {row.seq}: body is not valid JSON")
                continue
            if canonical(body) != row.body_bytes:
                c.fail(f"seq {row.seq}: body bytes are not canonical JSON (edited outside the tool)")
            row.body = body
            if body.get("seq") != position:
                c.fail(f"seq {row.seq}: body says seq {body.get('seq')} but it is entry #{position} (reordered or deleted rows)")
            if body.get("prev") != prev_hash:
                c.fail(f"seq {row.seq}: prev hash does not match entry #{position - 1} - the chain breaks here "
                       f"(an earlier entry was edited, deleted or reordered)")
            try:
                cosigs = json.loads(row.cosignatures_text)
            except json.JSONDecodeError:
                cosigs = []
                c.fail(f"seq {row.seq}: cosignatures column is corrupt")
            record = canonical({"body": body, "signature": row.signature.hex(), "cosignatures": cosigs})
            row.record_hash = hashlib.sha256(record).digest()
            row.leaf = hashlib.sha256(b"\x00" + record).digest()
            if row.record_hash != row.stored_hash:
                c.warn(f"seq {row.seq}: stored entry_hash no longer matches this entry's content (entry or hash column edited)")
            prev_hash = row.record_hash.hex()
        if not self.rows:
            c.fail("the case log is empty")
        c.detail = f"{len(self.rows)} entries"
        self.checks.append(c)

    def _check_signatures(self) -> list[dict]:
        c = Check("signatures", "Analyst signatures, key roster and witness co-signatures")
        roster: dict[str, dict] = {}
        compromised: dict[str, int] = {}
        # Revocations can be logged after the fact with an earlier compromise point.
        for row in self.rows:
            body = row.body or {}
            if body.get("action") == "key_revoke":
                d = body.get("details") or {}
                if d.get("compromised_since_seq") is not None:
                    compromised[d.get("key_id")] = int(d["compromised_since_seq"])
        ok_count = 0
        for row in self.rows:
            body = row.body
            entry = {"seq": row.seq, "signature": "invalid"}
            self.entries_out.append(entry)
            if body is None:
                continue
            entry.update({
                "time_claimed": body.get("time"), "actor": body.get("actor"), "action": body.get("action"),
                "key_id": body.get("key_id"), "exhibit": (body.get("exhibit") or {}).get("id"),
                "witness": (body.get("witness") or {}).get("actor"),
                "summary": _summary(body),
            })
            action, kid = body.get("action"), body.get("key_id")
            if row.seq == 0:
                if action != "case_open":
                    c.fail("entry 0 is not case_open; the case has no trusted roster")
                    continue
                for m in (body.get("details") or {}).get("roster", []):
                    raw = base64.b64decode(m["public_key"])
                    if key_fingerprint(raw) != m["key_id"]:
                        c.fail(f"genesis roster: key_id {m['key_id']} does not match its public key")
                    roster[m["key_id"]] = {**m, "raw": raw, "added_seq": 0, "revoked_seq": None}
            member = roster.get(kid)
            if member is None:
                c.fail(f"seq {row.seq}: signed by unknown key {kid} (not in the case roster)")
                continue
            if row.seq == 0 and member.get("role") != "admin":
                c.fail("entry 0 (case_open) is not signed by an admin key")
                continue
            if member["revoked_seq"] is not None and row.seq > member["revoked_seq"]:
                c.fail(f"seq {row.seq}: signed by {kid} ({member['actor']}) after it was revoked at seq {member['revoked_seq']}")
                continue
            if kid in compromised and row.seq >= compromised[kid]:
                c.fail(f"seq {row.seq}: signed by {kid} ({member['actor']}) after its declared compromise point "
                       f"(seq {compromised[kid]}); this entry cannot be trusted")
                continue
            if body.get("actor") != member["actor"]:
                c.fail(f"seq {row.seq}: actor '{body.get('actor')}' does not own key {kid} ({member['actor']})")
            if not sigs.ed25519_verify(member["raw"], DOMAIN_ENTRY + row.body_bytes, row.signature):
                c.fail(f"seq {row.seq}: Ed25519 signature by {member['actor']} ({kid}) does not verify - entry altered")
                continue
            if action in ("key_add", "key_revoke") and member.get("role") != "admin":
                c.fail(f"seq {row.seq}: {action} signed by non-admin {member['actor']}")
                continue
            witness = body.get("witness")
            if action == "handover" or witness:
                if not self._check_witness(row, witness, roster, c):
                    continue
            entry["signature"] = "valid"
            ok_count += 1
            d = body.get("details") or {}
            if action == "key_add":
                k = d.get("key", {})
                raw = base64.b64decode(k.get("public_key", ""))
                if key_fingerprint(raw) != k.get("key_id"):
                    c.fail(f"seq {row.seq}: key_add key_id does not match the public key")
                else:
                    roster[k["key_id"]] = {**k, "raw": raw, "added_seq": row.seq, "revoked_seq": None}
            elif action == "key_revoke" and d.get("key_id") in roster:
                roster[d["key_id"]]["revoked_seq"] = row.seq
                roster[d["key_id"]]["revocation"] = {"reason": d.get("reason"),
                                                     "compromised_since_seq": d.get("compromised_since_seq")}
        c.detail = f"{ok_count}/{len(self.rows)} entries carry a valid signature from an active roster key"
        self.checks.append(c)
        return [{k: v for k, v in m.items() if k != "raw"} for m in roster.values()]

    def _check_witness(self, row: Row, witness: dict | None, roster: dict, c: Check) -> bool:
        if not witness:
            c.fail(f"seq {row.seq}: handover without a witness")
            return False
        try:
            cosigs = json.loads(row.cosignatures_text)
        except json.JSONDecodeError:
            cosigs = []
        match = [s for s in cosigs if s.get("key_id") == witness.get("key_id")]
        member = roster.get(witness.get("key_id"))
        if not match or member is None:
            c.fail(f"seq {row.seq}: witness {witness.get('actor')} did not co-sign, or is not in the roster")
            return False
        if member["revoked_seq"] is not None and row.seq > member["revoked_seq"]:
            c.fail(f"seq {row.seq}: witness key {witness.get('key_id')} was already revoked")
            return False
        if not sigs.ed25519_verify(member["raw"], DOMAIN_WITNESS + row.body_bytes, unhex(match[0].get("signature")) or b""):
            c.fail(f"seq {row.seq}: witness co-signature by {witness.get('actor')} does not verify")
            return False
        if (row.body or {}).get("action") == "handover":
            to = ((row.body or {}).get("details") or {}).get("to")
            if to and to != member["actor"]:
                c.fail(f"seq {row.seq}: handover to '{to}' was co-signed by '{member['actor']}'")
                return False
        return True

    def _check_genesis(self) -> None:
        c = Check("genesis", "Case identity (pinned genesis entry)")
        if not self.rows or not self.rows[0].record_hash:
            c.fail("no genesis entry")
        elif self.expect_genesis:
            if self.rows[0].record_hash.hex() != self.expect_genesis.lower():
                c.fail(f"genesis is {self.rows[0].record_hash.hex()}, expected {self.expect_genesis} - "
                       "this is not the case you were given (or it was rebuilt from scratch)")
            else:
                c.detail = "matches the pinned value"
        else:
            c.status = "warn"
            c.detail = "not pinned; pass --expect-genesis with the value from the case paperwork"
        self.checks.append(c)

    # ------------------------------------------------------------------
    def _signed_exhibits(self) -> dict[str, tuple[int, dict]]:
        out: dict[str, tuple[int, dict]] = {}
        for row in self.rows:
            ex = (row.body or {}).get("exhibit")
            if ex and ex.get("id") and (row.body or {}).get("action") in ("acquire", "copy", "export"):
                out.setdefault(ex["id"], (row.seq, ex))
        return out

    def _check_exhibits(self, exhibit_rows, leaves: dict[str, list[bytes]]) -> None:
        signed = self._signed_exhibits()
        stored = {r[0]: r for r in exhibit_rows}
        for ex_id, (seq, ex) in signed.items():
            c = Check(f"exhibit:{ex_id}", f"Exhibit {ex_id} - {ex.get('label', '')}")
            h = tree.HASH_BY_NAME.get(ex.get("alg", "sha256"), tree.h_sha256)
            signed_root = unhex(ex.get("merkle_root"))
            if signed_root is None:
                c.fail("signed Merkle root is not valid hex (entry corrupted)")
                signed_root = b""
            info = {"id": ex_id, "label": ex.get("label"), "kind": ex.get("kind"), "size": ex.get("size"),
                    "chunk_size": ex.get("chunk_size"), "alg": ex.get("alg"), "leaves": ex.get("leaves"),
                    "merkle_root": ex.get("merkle_root"), "digests": ex.get("digests"), "parent": ex.get("parent"),
                    "recorded_seq": seq, "ewf": ex.get("ewf"), "evidence_rehashed": False}
            self.exhibits_out.append(info)
            cached = leaves.get(ex_id)
            cache_ok = False
            if cached is None or ex_id not in stored:
                c.warn("no stored leaf hashes; chunk-level localisation unavailable")
            elif len(cached) != ex.get("leaves") or tree.mth_large(cached, h) != signed_root:
                c.fail("stored leaf hashes do not reproduce the signed Merkle root (leaf table tampered)")
            else:
                cache_ok = True
            if ex.get("parent") and (row_action := self._action_at(seq)) == "copy":
                parent = signed.get(ex["parent"])
                if parent is None:
                    c.fail(f"copy of unknown exhibit {ex['parent']}")
                elif parent[1].get("merkle_root") != ex.get("merkle_root"):
                    c.fail(f"copy differs from its parent {ex['parent']} (Merkle roots differ)")
                else:
                    c.findings.append(f"bit-for-bit copy of {ex['parent']} (roots match)")
            if ex.get("ewf"):
                e = ex["ewf"]
                if e.get("md5_match") is False or e.get("sha1_match") is False:
                    c.warn("at acquisition, the E01's embedded MD5/SHA-1 did not match its media")
            path = self.evidence.get(ex_id)
            if path is not None:
                self._rehash(c, info, ex, path, cached if cache_ok else None, h, signed_root)
            c.detail = c.detail or f"root {ex.get('merkle_root', '')[:16]}… over {ex.get('leaves')} chunks"
            self.checks.append(c)
        for ex_id in stored:
            if ex_id not in signed:
                c = Check(f"exhibit:{ex_id}", f"Exhibit {ex_id}")
                c.fail("exhibit row exists but no signed entry records it")
                self.checks.append(c)

    def _action_at(self, seq: int) -> str | None:
        return (self.rows[seq].body or {}).get("action") if 0 <= seq < len(self.rows) else None

    def _rehash(self, c: Check, info: dict, ex: dict, path: Path, cached: list[bytes] | None, h, signed_root: bytes) -> None:
        chunk = int(ex.get("chunk_size", 4 << 20))
        fresh: list[bytes] = []
        sha256, md5, sha1 = hashlib.sha256(), hashlib.md5(), hashlib.sha1()
        total = 0
        if not path.exists():
            c.fail(f"evidence file {path} not found")
            return
        if ewfmedia.looks_like_e01(path):
            blocks = ewfmedia.media_blocks(path, chunk)
            layout = ewfmedia.read_layout(path)
        else:
            def file_blocks():
                with open(path, "rb") as fh:
                    while True:
                        b = fh.read(chunk)
                        if not b:
                            return
                        yield b
            blocks, layout = file_blocks(), None
        legacy = layout is not None  # MD5/SHA-1 are only needed to check an E01's embedded hashes
        try:
            for b in blocks:
                fresh.append(h(b"\x00" + b))
                sha256.update(b)
                if legacy:
                    md5.update(b)
                    sha1.update(b)
                total += len(b)
        except ewfmedia.E01Error as exc:
            c.fail(f"E01 container is damaged: {exc}")
            return
        info["evidence_rehashed"] = True
        info["rehash"] = {"path": str(path), "size": total, "sha256": sha256.hexdigest()}
        root = tree.mth_large(fresh, h)
        if root == signed_root and total == ex.get("size"):
            c.findings.append(f"evidence re-hashed: identical to the signed state ({len(fresh)} chunks)")
        else:
            if total != ex.get("size"):
                c.fail(f"evidence is {total} bytes; {ex.get('size')} bytes were recorded")
            if cached is not None:
                bad = [i for i in range(max(len(fresh), len(cached)))
                       if i >= len(fresh) or i >= len(cached) or fresh[i] != cached[i]]
                info["failing_chunks"] = bad
                for i in bad[:20]:
                    c.fail(f"chunk {i} differs: bytes {i * chunk}..{(i + 1) * chunk - 1}")
                if len(bad) > 20:
                    c.fail(f"... and {len(bad) - 20} more differing chunks")
            else:
                c.fail("evidence does not match the signed Merkle root (no trusted leaf cache to localise it)")
        digests = ex.get("digests") or {}
        if digests.get("sha256") and digests["sha256"] != sha256.hexdigest():
            c.fail("whole-file SHA-256 differs from the recorded value")
        if layout is not None:
            for name, stored_val, computed in (("MD5", layout.get("md5"), md5.hexdigest()), ("SHA-1", layout.get("sha1"), sha1.hexdigest())):
                if stored_val and any(ch != "0" for ch in stored_val) and stored_val != computed:
                    c.fail(f"E01 embedded {name} does not match the media")

    # ------------------------------------------------------------------
    def _check_anchors(self, anchor_rows) -> list[tuple[int, datetime, int]]:
        """Returns (tree_size, verified genTime, anchor-entry seq or -1) for every valid token."""
        c = Check("anchors", "RFC 3161 anchors of the log root")
        if not self.ca_bundles:
            c.warn("no CA bundle given (--tsa-ca); token signatures are checked but chains are not trusted")
        try:
            anchors_ca = tsp.load_anchors(self.ca_bundles)
        except Exception as exc:  # noqa: BLE001
            anchors_ca = []
            c.fail(f"cannot read CA bundle: {exc}")
        leaves = [r.leaf for r in self.rows if r.leaf]
        signed: dict[int, list[dict]] = {}
        for row in self.rows:
            if (row.body or {}).get("action") == "anchor":
                d = row.body.get("details") or {}
                signed.setdefault(int(d.get("tree_size", -1)), []).append({"seq": row.seq, **d})
                n = int(d.get("tree_size", -1))
                if n > row.seq:
                    c.fail(f"seq {row.seq}: anchor claims tree size {n}, larger than its own position")
                elif 0 < n <= len(leaves) and tree.mth_large(leaves[:n]).hex() != d.get("root"):
                    c.fail(f"seq {row.seq}: logged anchor root differs from the recomputed root of the first {n} entries")
        times: list[tuple[int, datetime, int]] = []
        for aid, size, root, tsa_name, url, token, gen_time in anchor_rows:
            root, token = bytes(root), bytes(token)
            out = {"id": aid, "tree_size": size, "tsa": tsa_name, "url": url, "root": root.hex()}
            self.anchors_out.append(out)
            if size > len(leaves):
                c.fail(f"anchor {aid} ({tsa_name}) covers {size} entries but the log has only {len(leaves)}: "
                       "the log was truncated after it was timestamped")
                out["status"] = "log truncated"
                continue
            recomputed = tree.mth_large(leaves[:size])
            if recomputed != root:
                c.fail(f"anchor {aid} ({tsa_name}): entries 0..{size - 1} no longer hash to the timestamped root "
                       "(modified after anchoring)")
                out["status"] = "root mismatch"
                continue
            logged = [a for a in signed.get(size, [])
                      if any(t.get("token_sha256") == hashlib.sha256(token).hexdigest() for t in a.get("tokens", []))]
            if not logged:
                c.warn(f"anchor {aid} ({tsa_name}) at size {size} is not referenced by any signed anchor entry")
            result = tsp.verify_token(token, root, anchors_ca)
            out.update(result.to_json())
            if not anchors_ca:
                result.problems = [p for p in result.problems if not p.startswith("chain:")]
                result.ok = not result.problems
            if result.ok:
                out["status"] = "valid"
                times.append((size, result.gen_time, logged[0]["seq"] if logged else -1))
            else:
                out["status"] = "invalid"
                c.fail(f"anchor {aid} ({tsa_name}): " + "; ".join(result.problems))
        times.sort(key=lambda t: t[0])
        for (s1, t1, _), (s2, t2, _) in zip(times, times[1:]):
            if s2 > s1 and t2 + TIME_TOLERANCE < t1:
                c.fail(f"timestamp for size {s2} ({t2.isoformat()}) is earlier than for size {s1} ({t1.isoformat()})")
        if not anchor_rows:
            c.warn("the log has never been anchored with a trusted timestamp")
        else:
            last = max(a[1] for a in anchor_rows)
            # The anchor entry that records a timestamp can only be covered by the next one,
            # so a trailing anchor entry is expected; anything else after the last anchor is not yet timestamped.
            pending = [r.seq for r in self.rows[last:] if (r.body or {}).get("action") != "anchor"]
            if pending:
                c.warn(f"entries {pending[0]}..{pending[-1]} are newer than the last anchor (not yet timestamped)")
            c.detail = f"{sum(1 for a in self.anchors_out if a.get('status') == 'valid')}/{len(anchor_rows)} tokens valid"
        self.checks.append(c)
        return times

    def _check_time(self, times: list[tuple[int, datetime, int]]) -> None:
        c = Check("time", "Claimed times vs. trusted timestamps")
        if not times:
            c.status = "skip"
            c.detail = "no valid timestamps to bound entry times"
            self.checks.append(c)
            return
        for entry in self.entries_out:
            seq = entry["seq"]
            # upper bound: earliest token whose tree contains this entry
            uppers = [t for size, t, _ in times if size > seq]
            # lower bound: a token logged in an anchor entry that precedes this entry
            lowers = [t for _, t, aseq in times if 0 <= aseq < seq]
            lo = max(lowers) if lowers else None
            hi = min(uppers) if uppers else None
            entry["provable_after"] = lo.isoformat() if lo else None
            entry["provable_before"] = hi.isoformat() if hi else None
            claimed = parse_time(entry.get("time_claimed") or "")
            if claimed is None:
                continue
            if hi and claimed > hi + TIME_TOLERANCE:
                c.fail(f"seq {seq}: claims {claimed.isoformat()} but a TSA proves it existed by {hi.isoformat()} "
                       "(writer clock ahead, or entry forged with a future time)")
            if lo and claimed + TIME_TOLERANCE < lo:
                c.fail(f"seq {seq}: claims {claimed.isoformat()} but follows a timestamp from {lo.isoformat()} "
                       "(backdated)")
        bounded = sum(1 for e in self.entries_out if e.get("provable_before"))
        c.detail = f"{bounded}/{len(self.entries_out)} entries have a TSA-proven upper time bound"
        self.checks.append(c)

    # ------------------------------------------------------------------
    def _check_checkpoints(self) -> None:
        if not self.checkpoint_paths:
            return
        leaves = [r.leaf for r in self.rows if r.leaf]
        anchors_ca = tsp.load_anchors(self.ca_bundles) if self.ca_bundles else []
        for path in self.checkpoint_paths:
            c = Check(f"checkpoint:{path.name}", f"Append-only since checkpoint {path.name}")
            cp = json.loads(path.read_text(encoding="utf-8"))
            m, root = int(cp["tree_size"]), bytes.fromhex(cp["root"])
            genesis = self.rows[0].record_hash.hex() if self.rows and self.rows[0].record_hash else None
            if cp.get("genesis") and cp["genesis"] != genesis:
                c.fail("checkpoint belongs to a different case (genesis differs)")
            if m > len(leaves):
                c.fail(f"checkpoint covers {m} entries; the log now has {len(leaves)} - entries were removed (truncation)")
            elif tree.mth_large(leaves[:m]) != root:
                c.fail(f"the first {m} entries no longer hash to the checkpoint root - history was rewritten")
            else:
                c.findings.append(f"log of {len(leaves)} entries is an append-only extension of the {m}-entry checkpoint")
            for ts in cp.get("timestamps", []):
                r = tsp.verify_token(base64.b64decode(ts["token"]), root, anchors_ca)
                if r.ok:
                    c.findings.append(f"checkpoint timestamp from {ts.get('tsa')} valid: {r.gen_time.isoformat()}")
                else:
                    c.fail(f"checkpoint timestamp from {ts.get('tsa')} invalid: {'; '.join(r.problems)}")
            self.checks.append(c)


def _summary(body: dict) -> str:
    d = body.get("details") or {}
    ex = body.get("exhibit") or {}
    action = body.get("action")
    if action == "case_open":
        return f"case opened: {d.get('title', '')} ({len(d.get('roster', []))} keys)"
    if action in ("acquire", "copy", "export"):
        return f"{ex.get('id')} {ex.get('label', '')} · {ex.get('size')} bytes · root {str(ex.get('merkle_root', ''))[:16]}…"
    if action == "handover":
        return f"{d.get('exhibit') or ''} handed to {d.get('to')}: {d.get('reason', '')}"
    if action == "anchor":
        return f"timestamped {d.get('tree_size')} entries via {', '.join(t.get('tsa', '') for t in d.get('tokens', []))}"
    if action == "key_add":
        return f"key added for {(d.get('key') or {}).get('actor')}"
    if action == "key_revoke":
        return f"key {d.get('key_id')} revoked ({d.get('reason')})"
    return d.get("note") or d.get("description") or action or ""


def verify_consistency_files(old: dict, new: dict, proof: dict) -> tuple[bool, str]:
    """Offline CT-style check: is ``new`` an append-only extension of ``old``?"""
    m, n = int(old["tree_size"]), int(new["tree_size"])
    if old.get("genesis") and new.get("genesis") and old["genesis"] != new["genesis"]:
        return False, "checkpoints are from different cases"
    path = [bytes.fromhex(p) for p in proof.get("proof", [])]
    ok = tree.verify_consistency(m, n, bytes.fromhex(old["root"]), bytes.fromhex(new["root"]), path)
    return ok, ("consistent: the newer log extends the older one" if ok else
                "INCONSISTENT: the newer log is not an append-only extension of the older one")
