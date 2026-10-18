"""RFC 3161 TimeStampToken verification (CMS SignedData, RFC 5652 / RFC 5816).

A token is accepted only if all of these hold:

1. it is SignedData encapsulating a TSTInfo
2. TSTInfo.messageImprint is SHA-256 of exactly the anchored log root
3. the signed attributes carry contentType = id-ct-TSTInfo and a
   messageDigest equal to the hash of the encapsulated TSTInfo
4. the ESS signing-certificate attribute names the certificate that signed
5. the signature over the signed attributes verifies with that certificate
6. that certificate has the (critical) timeStamping extended key usage
7. it chains to a CA in the bundle the *verifier* chose, valid at genTime
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from custodyverify import x509
from custodyverify.asn1 import TLV, decode

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"


@dataclass
class TokenResult:
    ok: bool
    problems: list[str] = field(default_factory=list)
    gen_time: datetime | None = None
    serial: int | None = None
    policy: str | None = None
    tsa_subject: str | None = None
    chain: list[str] = field(default_factory=list)
    signature_algorithm: str | None = None

    def to_json(self) -> dict:
        return {
            "ok": self.ok, "problems": self.problems,
            "gen_time": self.gen_time.isoformat() if self.gen_time else None,
            "serial": str(self.serial) if self.serial is not None else None, "policy": self.policy,
            "tsa_subject": self.tsa_subject, "chain": self.chain, "signature_algorithm": self.signature_algorithm,
            "revocation": "not checked (offline verifier)",
        }


def _attrs(signed_attrs: TLV) -> dict[str, list[TLV]]:
    out: dict[str, list[TLV]] = {}
    for attr in signed_attrs.items:
        oid_tlv, values = attr.items
        out[oid_tlv.oid()] = values.items
    return out


def verify_token(token: bytes, expected_digest: bytes, anchors: list[x509.Certificate]) -> TokenResult:
    res = TokenResult(ok=False)
    try:
        content_info = decode(token)
        ctype, wrapped = content_info.items
        if ctype.oid() != OID_SIGNED_DATA:
            res.problems.append("not a CMS SignedData token")
            return res
        sd = wrapped.items[0].items
        encap = sd[2].items
        if encap[0].oid() != OID_TSTINFO:
            res.problems.append("SignedData does not encapsulate TSTInfo")
            return res
        tst_der = encap[1].items[0].octets()
        certs: list[x509.Certificate] = []
        signer_infos = None
        for item in sd[3:]:
            if item.is_context(0):
                certs = [x509.parse_certificate(c.encoded) for c in item.items if c.is_universal(16)]
            elif item.is_universal(17):
                signer_infos = item.items
        if not signer_infos:
            res.problems.append("no SignerInfo")
            return res

        # -- TSTInfo ----------------------------------------------------
        tst = decode(tst_der).items
        res.policy = tst[1].oid()
        imprint = tst[2].items
        hash_name = x509.HASH_OIDS.get(imprint[0].items[0].oid())
        if hash_name != "sha256":
            res.problems.append(f"messageImprint uses {hash_name or 'an unknown hash'}, expected sha256")
        if imprint[1].octets() != expected_digest:
            res.problems.append("messageImprint does not match the anchored root (token is for different data)")
        res.serial = tst[3].integer()
        res.gen_time = tst[4].time()

        # -- SignerInfo -------------------------------------------------
        si = signer_infos[0].items
        sid = si[1]
        digest_alg = x509.HASH_OIDS.get(si[2].items[0].oid())
        signed_attrs = si[3] if si[3].is_context(0) else None
        if signed_attrs is None or digest_alg is None:
            res.problems.append("SignerInfo without signed attributes or with an unknown digest")
            return res
        sig_alg, signature = si[4], si[5].octets()
        res.signature_algorithm = sig_alg.items[0].oid()
        attrs = _attrs(signed_attrs)
        if [v.oid() for v in attrs.get(OID_CONTENT_TYPE, [])] != [OID_TSTINFO]:
            res.problems.append("signed contentType attribute is not id-ct-TSTInfo")
        md = attrs.get(OID_MESSAGE_DIGEST)
        if not md or md[0].octets() != hashlib.new(digest_alg, tst_der).digest():
            res.problems.append("messageDigest attribute does not match TSTInfo (token altered)")

        # find the signer certificate
        signer = None
        if sid.is_universal(16):
            issuer_der, serial = sid.items[0].encoded, sid.items[1].integer()
            signer = next((c for c in certs if c.issuer_der == issuer_der and c.serial == serial), None)
        elif sid.is_context(0):
            signer = next((c for c in certs if c.ski == sid.value), None)
        if signer is None:
            res.problems.append("signer certificate is not included in the token")
            return res
        res.tsa_subject = signer.subject

        # ESS: the signed attributes must name this certificate
        ess_ok = False
        if OID_SIGNING_CERT_V2 in attrs:
            ess_id = attrs[OID_SIGNING_CERT_V2][0].items[0].items[0].items
            h = "sha256"
            if ess_id[0].is_universal(16):
                h = x509.HASH_OIDS.get(ess_id[0].items[0].oid(), "sha256")
                cert_hash = ess_id[1].octets()
            else:
                cert_hash = ess_id[0].octets()
            ess_ok = hashlib.new(h, signer.der).digest() == cert_hash
        elif OID_SIGNING_CERT in attrs:
            cert_hash = attrs[OID_SIGNING_CERT][0].items[0].items[0].items[0].octets()
            ess_ok = hashlib.sha1(signer.der).digest() == cert_hash
        if not ess_ok:
            res.problems.append("ESS signing-certificate attribute does not identify the signer certificate")

        to_sign = b"\x31" + signed_attrs.encoded[1:]
        if not x509.verify_signature(signer.key, sig_alg, to_sign, signature, default_hash=digest_alg):
            res.problems.append("TSA signature over the signed attributes does not verify")

        if x509.EKU_TIME_STAMPING not in signer.eku:
            res.problems.append("TSA certificate lacks the timeStamping extended key usage")
        elif not signer.eku_critical:
            res.problems.append("TSA certificate timeStamping EKU is not marked critical (RFC 3161 2.3)")

        chain = x509.build_chain(signer, [c for c in certs if c is not signer], anchors, res.gen_time)
        res.chain = [c.subject for c in chain.path]
        res.problems.extend(f"chain: {p}" for p in chain.problems)
    except Exception as exc:  # noqa: BLE001 - malformed tokens fail cleanly, never silently
        res.problems.append(f"malformed token: {type(exc).__name__}: {exc}")
    res.ok = not res.problems
    return res


def load_anchors(paths: list[Path]) -> list[x509.Certificate]:
    out: list[x509.Certificate] = []
    for p in paths:
        p = Path(p)
        files = sorted(p.glob("*.pem")) if p.is_dir() else [p]
        for f in files:
            out.extend(x509.load_pem_bundle(f))
    return out
