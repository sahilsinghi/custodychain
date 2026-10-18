"""RFC 3161 trusted timestamps for custody-log roots.

A local clock proves nothing, so the log's Merkle root is periodically sent
to one or more Time-Stamping Authorities. Each returns a signed token
binding that root to a time from an independent party. The raw token is
stored as-is; the verifier checks the CMS signature and the TSA's chain
against a CA bundle chosen by the person verifying, not by the writer.

Two TSAs are used by default so no single authority is a point of trust.
Tokens are cached in the case database and roots are batched (anchor every
N entries or on demand) because free TSAs rate-limit.
"""

from __future__ import annotations

import os
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime

from custodychain import der

SHA256_OID = "2.16.840.1.101.3.4.2.1"
ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
ID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4"

PUBLIC_TSAS = {
    "freetsa": "https://freetsa.org/tsr",
    "digicert": "http://timestamp.digicert.com",
    "sectigo": "http://timestamp.sectigo.com",
    "globalsign": "http://rfc3161timestamp.globalsign.com/advanced",
}
DEFAULT_TSAS = ("freetsa", "digicert")


class TimestampError(Exception):
    pass


@dataclass
class Token:
    tsa: str
    url: str
    token: bytes  # DER ContentInfo (the TimeStampToken)
    gen_time: datetime
    serial: int
    nonce: int | None
    policy: str

    def summary(self) -> dict:
        return {"tsa": self.tsa, "url": self.url, "gen_time": self.gen_time.isoformat(),
                "serial": str(self.serial), "policy": self.policy}


def build_request(digest: bytes, nonce: int) -> bytes:
    if len(digest) != 32:
        raise ValueError("SHA-256 digest expected")
    imprint = der.seq(der.seq(der.oid(SHA256_OID), der.null()), der.octets(digest))
    return der.seq(der.integer(1), imprint, der.integer(nonce), der.boolean(True))


def parse_response(resp: bytes) -> bytes:
    """Return the TimeStampToken (ContentInfo DER) or raise with the TSA's status."""
    root = der.parse(resp)
    parts = root.children()
    status_info = parts[0].children()
    status = status_info[0].as_int()
    if status not in (0, 1):  # granted, grantedWithMods
        text = ""
        if len(status_info) > 1 and status_info[1].tag == 0x30:
            text = "; ".join(c.content.decode("utf-8", "replace") for c in status_info[1].children())
        raise TimestampError(f"TSA refused the request (status {status}) {text}".strip())
    if len(parts) < 2:
        raise TimestampError("granted response without a token")
    return parts[1].raw


def tstinfo_from_token(token: bytes) -> der.Node:
    content_info = der.parse(token).children()
    if content_info[0].as_oid() != ID_SIGNED_DATA:
        raise TimestampError("token is not CMS SignedData")
    signed_data = content_info[1].children()[0].children()
    encap = signed_data[2].children()
    if encap[0].as_oid() != ID_CT_TSTINFO:
        raise TimestampError("token does not encapsulate TSTInfo")
    octet = encap[1].children()[0]
    return der.parse(octet.content)


def check_token(token: bytes, digest: bytes, nonce: int | None) -> tuple[datetime, int, int | None, str]:
    """Writer-side sanity checks; the full cryptographic check is the verifier's job."""
    tst = tstinfo_from_token(token).children()
    policy = tst[1].as_oid()
    imprint = tst[2].children()
    if imprint[0].children()[0].as_oid() != SHA256_OID or imprint[1].content != digest:
        raise TimestampError("TSA token does not timestamp the requested digest")
    serial = tst[3].as_int()
    gen_time = tst[4].as_time()
    token_nonce = None
    for item in tst[5:]:
        if item.tag == 0x02:
            token_nonce = item.as_int()
    if nonce is not None and token_nonce != nonce:
        raise TimestampError("TSA token nonce does not match the request (replay?)")
    return gen_time, serial, token_nonce, policy


MAX_RESPONSE = 1 << 20  # real TSA responses are a few KiB


def request_token(url: str, digest: bytes, name: str = "", timeout: int = 30) -> Token:
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise TimestampError(f"{name or url}: TSA URL must be http(s)")
    nonce = int.from_bytes(os.urandom(8), "big") >> 1
    req = urllib.request.Request(
        url, data=build_request(digest, nonce), method="POST",
        headers={"Content-Type": "application/timestamp-query", "User-Agent": "custodychain/0.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310 - http(s) only, checked above
            body = resp.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise TimestampError(f"{name or url}: response larger than {MAX_RESPONSE} bytes")
    except OSError as exc:
        raise TimestampError(f"{name or url}: {exc}") from exc
    token = parse_response(body)
    gen_time, serial, token_nonce, policy = check_token(token, digest, nonce)
    return Token(name or url, url, token, gen_time, serial, token_nonce, policy)
