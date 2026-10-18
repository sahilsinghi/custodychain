# Security

The threat model (insider edits, clock tampering, key theft) and how each threat is addressed is in [docs/design.md](docs/design.md). This file covers the robustness of the tools themselves.

## The verifier treats everything as hostile

`custody-verify` must give a correct pass/fail on a case file that someone may have crafted to fool it or crash it.

| Input | Handling |
|---|---|
| Case database | Copied first, then opened **read-only** with SQLite's defensive mode on and `trusted_schema` off. Every check is guarded: malformed data produces a failed check, never a crash (Hypothesis property tests). |
| Revocations | A `key_revoke` entry can declare an earlier compromise point, but only revocations whose admin signature verifies are honoured. A forged row cannot discredit genuine entries. |
| E01 containers | The section chain must move forward inside the file, so a looping chain is rejected instead of hanging. Compressed chunks may not inflate beyond the volume's chunk size, so decompression bombs are refused. Chunk sizes are bounded. |
| Recorded chunk size | Must be within 512 B–1 GiB before evidence is re-hashed. |
| RFC 3161 tokens | Checks cover the imprint, messageDigest, ESS signing-certificate binding, the signature, a critical timeStamping EKU, and the chain to *your* CA bundle at genTime. Malformed tokens fail cleanly. |
| Signatures | Pure-Python verification (no secrets handled), cross-checked against `cryptography`:<br>• RSA PKCS#1 v1.5 compares the full encoded message, so no Bleichenbacher '06 forgeries.<br>• PSS checks padding and salt.<br>• ECDSA range-checks `r`, `s` and the point coordinates.<br>• Ed25519 rejects `s ≥ L` and non-canonical points. |

The writer's E01 reader (`custody acquire`) has the same section-chain and inflate limits. The TSA client accepts only http(s) URLs, caps responses at 1 MiB and checks its nonce.

## Keys

- Analyst keys are scrypt-encrypted PKCS#8, created with `O_EXCL` and mode `0600`.
- `CUSTODY_KEY_PASSWORD[_<KEY>]` exists for automation. Environment variables are visible to other processes of the same user, so prefer the interactive prompt on shared machines.

## Known limits

- **Certificate revocation:** TSA certificates are not checked for revocation (OCSP/CRL), because the verifier runs offline. The report says so.
- **Path validation is minimal:** issuer signature, CA flag, name chaining and validity at genTime. Name constraints, policies and path-length limits are not enforced. Keep the CA bundle limited to the TSAs you actually use.
- **Pin the genesis:** a case rebuilt from scratch with new keys verifies internally. Pass `--expect-genesis` with the value from the case paperwork; without it the verifier warns.

Checked with: bandit and semgrep (only format-mandated MD5/SHA-1 for E01 hashes and ESS v1 remain), pip-audit (no known vulnerabilities), and the regression tests in `tests/test_hardening.py`.

## Reporting

Please open a private security advisory on the repository instead of a public issue.
