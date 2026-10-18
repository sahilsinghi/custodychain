"""Just enough X.509 to validate a TSA certificate chain.

Checks performed for each link: the issuer's public key verifies the
child's signature, the issuer is a CA (basicConstraints), names chain, and
every certificate was valid at the validation time (the token's genTime -
timestamps are validated as of the moment they were issued). Revocation is
not checked: the verifier runs offline, and the report says so.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from custodyverify import sigs
from custodyverify.asn1 import TLV, decode

OID_RSA = "1.2.840.113549.1.1.1"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_EC = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
SIG_ALGS = {
    "1.2.840.113549.1.1.5": ("rsa", "sha1"),
    "1.2.840.113549.1.1.11": ("rsa", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa", "sha512"),
    "1.2.840.10045.4.3.2": ("ecdsa", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa", "sha512"),
    OID_ED25519: ("ed25519", None),
}
HASH_OIDS = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST"}
EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"


@dataclass
class PublicKeyInfo:
    kind: str  # rsa | ec | ed25519
    rsa: tuple[int, int] | None = None
    curve_oid: str | None = None
    point: bytes | None = None
    raw: bytes | None = None


@dataclass
class Certificate:
    der: bytes
    tbs: bytes
    sig_alg: TLV
    signature: bytes
    serial: int
    issuer_der: bytes
    subject_der: bytes
    issuer: str
    subject: str
    not_before: datetime
    not_after: datetime
    key: PublicKeyInfo
    is_ca: bool = False
    key_usage: int | None = None
    eku: list[str] = field(default_factory=list)
    eku_critical: bool = False
    ski: bytes | None = None


def _name(tlv: TLV) -> str:
    parts = []
    for rdn in tlv.items:
        for atv in rdn.items:
            oid, value = atv.items[0].oid(), atv.items[1]
            parts.append(f"{NAME_OIDS.get(oid, oid)}={value.text()}")
    return ", ".join(parts)


def _public_key(spki: TLV) -> PublicKeyInfo:
    alg, key_bits = spki.items
    alg_items = alg.items
    oid = alg_items[0].oid()
    data = key_bits.bits()
    if oid in (OID_RSA, OID_RSA_PSS):
        n, e = decode(data).items
        return PublicKeyInfo("rsa", rsa=(n.integer(), e.integer()))
    if oid == OID_EC:
        return PublicKeyInfo("ec", curve_oid=alg_items[1].oid(), point=data)
    if oid == OID_ED25519:
        return PublicKeyInfo("ed25519", raw=data)
    return PublicKeyInfo(oid)


def parse_certificate(der: bytes) -> Certificate:
    cert = decode(der)
    tbs, sig_alg, sig = cert.items
    fields = tbs.items
    i = 1 if fields[0].is_context(0) else 0
    serial = fields[i].integer()
    issuer, validity, subject, spki = fields[i + 2], fields[i + 3], fields[i + 4], fields[i + 5]
    nb, na = validity.items
    c = Certificate(
        der=der, tbs=tbs.encoded, sig_alg=sig_alg, signature=sig.bits(), serial=serial,
        issuer_der=issuer.encoded, subject_der=subject.encoded, issuer=_name(issuer), subject=_name(subject),
        not_before=nb.time(), not_after=na.time(), key=_public_key(spki),
    )
    for f in fields[i + 6:]:
        if not f.is_context(3):
            continue
        for ext in f.items[0].items:
            parts = ext.items
            oid = parts[0].oid()
            critical = parts[1].boolean() if len(parts) == 3 else False
            value = decode(parts[-1].octets())
            if oid == "2.5.29.19":
                items = value.items
                c.is_ca = bool(items) and items[0].is_universal(1) and items[0].boolean()
            elif oid == "2.5.29.15":
                bits = value.value
                c.key_usage = int.from_bytes(bits[1:], "big") >> bits[0] if len(bits) > 1 else 0
            elif oid == "2.5.29.37":
                c.eku = [x.oid() for x in value.items]
                c.eku_critical = critical
            elif oid == "2.5.29.14":
                c.ski = value.octets()
    return c


def load_pem_bundle(path: Path) -> list[Certificate]:
    text = Path(path).read_text(encoding="ascii", errors="ignore")
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", text, re.S)
    return [parse_certificate(base64.b64decode("".join(b.split()))) for b in blocks]


def verify_signature(key: PublicKeyInfo, alg: TLV, data: bytes, signature: bytes,
                     default_hash: str | None = None) -> bool:
    items = alg.items
    oid = items[0].oid()
    if oid == OID_RSA_PSS:
        hash_name, salt, mgf_hash = "sha1", 20, None
        if len(items) > 1:
            for p in items[1].items:
                if p.is_context(0):
                    hash_name = HASH_OIDS[p.items[0].items[0].oid()]
                elif p.is_context(1):
                    mgf_hash = HASH_OIDS[p.items[0].items[1].items[0].oid()]
                elif p.is_context(2):
                    salt = p.items[0].integer()
        return key.rsa is not None and sigs.rsa_pss_verify(key.rsa[0], key.rsa[1], data, signature, hash_name, salt,
                                                           mgf_hash or hash_name)
    if oid == OID_RSA:  # CMS: "rsaEncryption" + the SignerInfo digest algorithm
        kind, hash_name = "rsa", default_hash
    elif oid in SIG_ALGS:
        kind, hash_name = SIG_ALGS[oid]
    else:
        return False
    if kind == "rsa":
        return key.kind == "rsa" and hash_name is not None and sigs.rsa_pkcs1v15_verify(
            key.rsa[0], key.rsa[1], data, signature, hash_name)
    if kind == "ecdsa":
        curve = sigs.CURVES.get(key.curve_oid or "")
        if key.kind != "ec" or curve is None:
            return False
        point = sigs.ec_point(curve, key.point or b"")
        if point is None:
            return False
        r, s = (x.integer() for x in decode(signature).items)
        return sigs.ecdsa_verify(curve, point, data, r, s, hash_name)
    if kind == "ed25519":
        return key.kind == "ed25519" and sigs.ed25519_verify(key.raw or b"", data, signature)
    return False


@dataclass
class ChainResult:
    ok: bool
    path: list[Certificate]
    problems: list[str]


def build_chain(leaf: Certificate, intermediates: list[Certificate], anchors: list[Certificate],
                at: datetime) -> ChainResult:
    problems: list[str] = []
    path = [leaf]
    current = leaf
    for _ in range(8):
        if not current.not_before <= at <= current.not_after:
            problems.append(f"'{current.subject}' was not valid at {at.isoformat()} "
                            f"({current.not_before.date()} .. {current.not_after.date()})")
        if any(a.der == current.der for a in anchors):
            return ChainResult(not problems, path, problems)
        issuer = None
        for candidate in [a for a in anchors] + [c for c in intermediates if c not in path]:
            if candidate.subject_der != current.issuer_der:
                continue
            if verify_signature(candidate.key, current.sig_alg, current.tbs, current.signature):
                issuer = candidate
                break
        if issuer is None:
            problems.append(f"no trusted issuer found for '{current.subject}' (issuer '{current.issuer}')")
            return ChainResult(False, path, problems)
        if not issuer.is_ca:
            problems.append(f"issuer '{issuer.subject}' is not a CA")
        path.append(issuer)
        if any(a.der == issuer.der or (a.subject_der == issuer.subject_der and a.key == issuer.key) for a in anchors):
            if not issuer.not_before <= at <= issuer.not_after:
                problems.append(f"trust anchor '{issuer.subject}' was not valid at {at.isoformat()}")
            return ChainResult(not problems, path, problems)
        current = issuer
    problems.append("chain longer than 8 certificates")
    return ChainResult(False, path, problems)
