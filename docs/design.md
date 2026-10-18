# CustodyChain design and threat model

## What it must prove

Months after seizure, someone who trusts neither the lab's software nor its staff must be
able to check four things:

1. **Integrity.** The exhibit being examined is bit-for-bit the one seized, and if it is
   not, which bytes changed.
2. **History.** The custody log has not been edited, reordered or cut since each entry
   was written.
3. **Attribution.** Each action was taken by the analyst it names, using a key the case
   had authorised at that moment.
4. **Time.** Each action happened no later than (and, where possible, no earlier than) a
   time vouched for by an independent party.

## Data structures

```
evidence file ─► 4 MiB chunks ─► H(0x00‖chunk) leaves ─► RFC 9162 Merkle root (per exhibit)

entry body  = canonical JSON {v, case, seq, prev, time, actor, key_id, action, exhibit, details, witness}
signature   = Ed25519(actor key,   "custodychain/v1/entry\0"   ‖ body)
cosignature = Ed25519(witness key, "custodychain/v1/witness\0" ‖ body)     (handover)
record      = canonical JSON {body, signature, cosignatures}
entry hash  = SHA-256(record)            ─► next entry's prev
log leaf    = SHA-256(0x00 ‖ record)     ─► RFC 9162 log root ─► RFC 3161 TSA tokens
```

* **Domain separation everywhere.** Merkle leaves vs nodes use the RFC 9162 `0x00`/`0x01`
  prefixes, which blocks the second-preimage trick of presenting an interior node as a leaf.
  Entry and witness signatures use different context strings, so a witness co-signature can
  never be replayed as an authorship signature.
* **Canonical JSON** (sorted keys, no whitespace, UTF-8, no floats) is what gets signed.
  The verifier rejects any body that does not re-encode to identical bytes, so there is
  only one valid encoding of every entry.
* **The log commits to signatures**, not just bodies: the Merkle leaf is the full record,
  so an anchored root also fixes who signed.
* **E01 images are hashed as media**, the bytes the suspect drive held, not the
  container. Re-imaging with a different tool, compression level or segment size gives
  the same Merkle root. The image's own embedded MD5 and SHA-1 are verified against the
  decoded media and recorded alongside.

## Components

| Component | Where | Notes |
|---|---|---|
| Hasher | `custodychain/hasher.py` | Streams fixed 4 MiB chunks; leaf hashing in N worker processes reading disjoint ranges; whole-file SHA-256 / SHA-1 / MD5 each in its own process; checkpoints leaves to SQLite so a crash resumes where it stopped; refuses evidence whose size or mtime changed mid-hash; warns (or with `--require-readonly` refuses) when the evidence is writable. |
| Ledger | `custodychain/ledger.py` | SQLite in WAL mode with `synchronous=FULL`. No UPDATE/DELETE code paths for entries, plus triggers that abort them. Neither is a security boundary; the cryptography is. |
| Signer | `custodychain/keys.py` | Ed25519; private keys in scrypt-encrypted PKCS#8 files (mode 0600); key ID = first 16 bytes of SHA-256(public key). |
| Anchor | `custodychain/anchor.py` | RFC 3161 over HTTP with a random nonce; the token is stored raw; FreeTSA + DigiCert by default (Sectigo, GlobalSign or any URL configurable); the anchor is itself logged as an entry. |
| Verifier | `custodyverify/` | Separate package, standard library only: its own DER parser, Ed25519 (RFC 8032), RSA PKCS#1 v1.5 / PSS, ECDSA P-256/384/521, X.509 chain building, CMS/RFC 3161 checks and Merkle code. Works on a copy of the database. |
| Reporter | `custodychain/report.py` | Renders the verifier's JSON as a PDF that includes the command to re-run the verification. |

## Threat model

| Threat | Example | Defence | Residual risk |
|---|---|---|---|
| **Insider edits an entry** | Changes "LNK files parsed" to "nothing found" directly in SQLite | Entry signature fails at that row; the next row's `prev` no longer matches; every anchored root covering it no longer recomputes | None, if the verifier has the original genesis value or any earlier anchor |
| **Insider deletes or reorders entries** | Removes an embarrassing handover | Seq gaps, `body.seq` ≠ position, `prev` mismatch; anchors covering the deleted rows fail | — |
| **Insider truncates the log and re-anchors** | Drops the last 3 entries and timestamps the shorter log | Surviving anchor rows exceed the log size ("truncated after it was timestamped"); exported checkpoints given to the other side fail the append-only check | If the insider also deletes all anchor rows *and* nobody holds an earlier checkpoint, a shorter but internally consistent log can be presented. Mitigation: hand checkpoints to the prosecutor/defence at each milestone (`custody checkpoint`), or publish roots to a transparency log (future work). |
| **Insider rebuilds the whole case** | New keys, new log, re-hashed evidence | `--expect-genesis` pinning: the genesis hash is recorded in the case paperwork at case opening | Requires the paperwork to be kept. TSA tokens on the forged log carry the forgery date, which won't match the claimed history. |
| **Clock tampering** | Analyst sets the workstation clock back to make an action look earlier | Claimed time is never trusted. The verifier derives a provable window per entry: before the first TSA token covering it, after any token logged before it, and flags claimed times outside that window (5-minute tolerance) | Window width depends on anchoring frequency; anchor more often for tighter bounds |
| **Evidence substitution** | Swaps the working copy for a modified one | Copies must reproduce the parent's Merkle root to be logged; the verifier re-hashes supplied evidence and names every differing 4 MiB chunk and byte range | — |
| **Leaf-cache tampering** | Edits stored chunk hashes to hide a modified chunk | Stored leaves must reproduce the *signed* root; otherwise the cache is reported tampered and localisation is not used | — |
| **Key theft** | An analyst's key file and password are stolen | Admin revokes with `compromised_since_seq`; entries signed by that key from that point are rejected, earlier work stays valid | Entries forged before discovery and before the declared point stay valid. Hardware keys (PIV/YubiKey) would remove key-file theft. |
| **Lost key** | Laptop wiped | Admin revokes (`lost`) and adds a new key; history stays verifiable | — |
| **Rogue analyst escalates** | Analyst adds their own second key | `key_add` / `key_revoke` must be signed by an active admin key; the verifier replays the roster from genesis | A compromised admin key can add keys. Mitigate with a two-person rule (future: require admin co-signature). |
| **Unwitnessed handover** | Analyst claims to have passed the exhibit on | Handovers require the receiving analyst's co-signature, checked against the roster | — |
| **Compromised or wrong TSA** | A TSA issues a token for any time it likes | Two independent TSAs by default; the verifier picks its own CA bundle (`--tsa-ca`), checks the timeStamping EKU, ESS signing-certificate binding and chain validity at genTime, and requires genTime monotonicity across anchors | Revocation (CRL/OCSP) is not checked offline. A TSA colluding with an insider can only affect its own tokens. |
| **Malformed input crashes the verifier** | Fuzzed bytes in the database | Every check is isolated; malformed data produces a failed check, never a crash (found and fixed by Hypothesis) | — |
| **Bug in the writer hides a problem** | Writer computes a wrong hash consistently | The verifier shares no code with the writer and uses separately written primitives; tests cross-check both implementations against each other, RFC test vectors and `cryptography` | Both could still share a misreading of a spec |

## Why these choices

* **Fixed 4 MiB leaves.** Small enough to localise a flipped byte to 4 MiB and keep
  inclusion proofs at about 17 hashes for a 500 GB disk. Large enough that the leaf
  table is about 4 MB per 500 GB.
* **SHA-256 by default, BLAKE3 optional.** SHA-256 is what courts and other tools already
  recognise. On Apple Silicon, hardware SHA-256 is also faster than software BLAKE3 in
  this implementation (see [benchmarks](benchmarks.md)).
* **SQLite.** One file that travels with the case folder. WAL keeps a crash during an append
  from corrupting earlier entries. The verifier copies the database before opening it, so
  verification never writes to evidence.
* **RFC 9162 structure for both trees.** Inclusion and consistency proofs are
  standard and the same proofs CT auditors already use. The writer's iterative
  implementation and the verifier's recursive one are tested against CT's published
  vectors.

## Known gaps / future work

* Hardware-backed analyst keys (PIV), two-person admin actions.
* Publishing anchored roots to a public transparency log (e.g. Sigstore Rekor) as a third
  independent witness. This is an outward publication, so it is left as an explicit opt-in.
* CRL/OCSP checking of TSA certificates when online.
* A second-language verifier (Go or Rust). The stdlib-only Python verifier is designed
  so it can be ported file by file.
