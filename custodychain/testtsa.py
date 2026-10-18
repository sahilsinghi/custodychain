"""A local RFC 3161 Time-Stamping Authority for tests, demos and air-gapped labs.

It issues real tokens (CMS SignedData over TSTInfo, ESS signingCertificateV2,
TSA certificate with the critical timeStamping EKU) from its own throwaway
CA, so the verifier exercises exactly the same code path as with FreeTSA or
DigiCert. Tokens from it only prove time to someone who trusts its CA,
which is the point of the "wrong CA bundle" test.

    custody tsa init lab-tsa/            # create CA + TSA certificate
    custody tsa serve lab-tsa/ --port 3161
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from custodychain import der
from custodychain.anchor import ID_CT_TSTINFO, ID_SIGNED_DATA, SHA256_OID

OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
TEST_POLICY = "1.3.6.1.4.1.55555.3161.1"


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CustodyChain Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _new_key(kind: str):
    if kind == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@dataclass
class TestTSA:
    __test__ = False  # not a pytest test class
    ca_cert: x509.Certificate
    tsa_cert: x509.Certificate
    tsa_key: object
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    serial: int = 1

    # -- creation ------------------------------------------------------
    @classmethod
    def create(cls, kind: str = "ec", name: str = "CustodyChain Lab TSA") -> "TestTSA":
        now = datetime.now(timezone.utc) - timedelta(days=1)
        ca_key = _new_key(kind)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(_name(f"{name} Root CA"))
            .issuer_name(_name(f"{name} Root CA"))
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        tsa_key = _new_key(kind)
        tsa_cert = (
            x509.CertificateBuilder()
            .subject_name(_name(name))
            .issuer_name(ca_cert.subject)
            .public_key(tsa_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(tsa_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return cls(ca_cert, tsa_cert, tsa_key)

    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "ca.pem").write_bytes(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        (directory / "tsa.pem").write_bytes(self.tsa_cert.public_bytes(serialization.Encoding.PEM))
        key = self.tsa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())
        fd = os.open(directory / "tsa.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)

    @classmethod
    def load(cls, directory: Path) -> "TestTSA":
        ca = x509.load_pem_x509_certificate((directory / "ca.pem").read_bytes())
        tsa = x509.load_pem_x509_certificate((directory / "tsa.pem").read_bytes())
        key = serialization.load_pem_private_key((directory / "tsa.key").read_bytes(), password=None)
        return cls(ca, tsa, key)

    # -- issuing -------------------------------------------------------
    def tstinfo(self, digest: bytes, nonce: int | None, when: datetime) -> bytes:
        self.serial += 1
        fields = [
            der.integer(1),
            der.oid(TEST_POLICY),
            der.seq(der.seq(der.oid(SHA256_OID), der.null()), der.octets(digest)),
            der.integer(int.from_bytes(os.urandom(8), "big") << 16 | self.serial),
            der.generalized_time(when),
            der.seq(der.integer(1)),  # accuracy: 1 second
        ]
        if nonce is not None:
            fields.append(der.integer(nonce))
        return der.seq(*fields)

    def _sign(self, data: bytes) -> tuple[bytes, bytes]:
        if isinstance(self.tsa_key, ec.EllipticCurvePrivateKey):
            return der.seq(der.oid(OID_ECDSA_SHA256)), self.tsa_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return der.seq(der.oid(OID_SHA256_RSA), der.null()), self.tsa_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    def token(self, digest: bytes, nonce: int | None = None, when: datetime | None = None) -> bytes:
        when = when or self.clock()
        tst = self.tstinfo(digest, nonce, when)
        cert_der = self.tsa_cert.public_bytes(serialization.Encoding.DER)
        attrs = [
            der.seq(der.oid(OID_CONTENT_TYPE), der.set_of(der.oid(ID_CT_TSTINFO))),
            der.seq(der.oid(OID_SIGNING_TIME), der.set_of(der.tlv(0x17, when.strftime("%y%m%d%H%M%SZ").encode()))),
            der.seq(der.oid(OID_MESSAGE_DIGEST), der.set_of(der.octets(hashlib.sha256(tst).digest()))),
            der.seq(der.oid(OID_SIGNING_CERT_V2), der.set_of(der.seq(der.seq(der.seq(der.octets(hashlib.sha256(cert_der).digest())))))),
        ]
        attrs_content = b"".join(sorted(attrs))  # DER SET OF ordering
        # The signature covers the attributes encoded as a SET (tag 0x31); inside
        # SignerInfo the same content is carried as [0] IMPLICIT (tag 0xA0).
        sig_alg, signature = self._sign(der.tlv(0x31, attrs_content))
        issuer_and_serial = der.seq(self.tsa_cert.issuer.public_bytes(), der.integer(self.tsa_cert.serial_number))
        signer_info = der.seq(
            der.integer(1),
            issuer_and_serial,
            der.seq(der.oid(SHA256_OID), der.null()),
            der.tlv(0xA0, attrs_content),
            sig_alg,
            der.octets(signature),
        )
        signed_data = der.seq(
            der.integer(3),
            der.set_of(der.seq(der.oid(SHA256_OID), der.null())),
            der.seq(der.oid(ID_CT_TSTINFO), der.explicit(0, der.octets(tst))),
            der.tlv(0xA0, cert_der),
            der.set_of(signer_info),
        )
        return der.seq(der.oid(ID_SIGNED_DATA), der.explicit(0, signed_data))

    def respond(self, request: bytes) -> bytes:
        req = der.parse(request).children()
        imprint = req[1].children()
        digest = imprint[1].content
        nonce = None
        for item in req[2:]:
            if item.tag == 0x02:
                nonce = item.as_int()
        token = self.token(digest, nonce)
        return der.seq(der.seq(der.integer(0)), token)


def serve(tsa: TestTSA, host: str = "127.0.0.1", port: int = 3161) -> http.server.ThreadingHTTPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - http.server API
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            try:
                reply = tsa.respond(body)
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
            except Exception as exc:  # noqa: BLE001
                reply = json.dumps({"error": str(exc)}).encode()
                self.send_response(400)
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, *args):  # quiet
            pass

    server = http.server.ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
