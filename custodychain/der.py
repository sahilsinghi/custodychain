"""Minimal DER encoder / decoder for the RFC 3161 structures the writer needs.

(The independent verifier has its own, separately written decoder.)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

# -- encoding ---------------------------------------------------------------


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(sorted(items)))  # DER: SET OF sorted by encoding


def integer(v: int) -> bytes:
    if v == 0:
        return tlv(0x02, b"\x00")
    length = (v.bit_length() + 8) // 8 if v > 0 else ((-v - 1).bit_length() + 8) // 8
    return tlv(0x02, v.to_bytes(length, "big", signed=True))


def boolean(v: bool) -> bytes:
    return tlv(0x01, b"\xff" if v else b"\x00")


def null() -> bytes:
    return b"\x05\x00"


def octets(v: bytes) -> bytes:
    return tlv(0x04, v)


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body.extend(reversed(chunk))
    return tlv(0x06, bytes(body))


def generalized_time(t: datetime) -> bytes:
    t = t.astimezone(timezone.utc)
    text = t.strftime("%Y%m%d%H%M%S")
    if t.microsecond:
        text += "." + f"{t.microsecond:06d}".rstrip("0")
    return tlv(0x18, (text + "Z").encode("ascii"))


def utf8(text: str) -> bytes:
    return tlv(0x0C, text.encode("utf-8"))


def explicit(n: int, inner: bytes) -> bytes:
    return tlv(0xA0 | n, inner)


def implicit_constructed(n: int, inner_content: bytes) -> bytes:
    return tlv(0xA0 | n, inner_content)


# -- decoding ---------------------------------------------------------------

@dataclass
class Node:
    tag: int
    content: bytes
    raw: bytes

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> list["Node"]:
        out, i = [], 0
        while i < len(self.content):
            node, i = read(self.content, i)
            out.append(node)
        return out

    def as_int(self) -> int:
        return int.from_bytes(self.content, "big", signed=True)

    def as_oid(self) -> str:
        b = self.content
        parts = [b[0] // 40, b[0] % 40]
        v = 0
        for byte in b[1:]:
            v = (v << 7) | (byte & 0x7F)
            if not byte & 0x80:
                parts.append(v)
                v = 0
        return ".".join(map(str, parts))

    def as_time(self) -> datetime:
        text = self.content.decode("ascii").rstrip("Z")
        if self.tag == 0x17:  # UTCTime
            return datetime.strptime(text, "%y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        frac = ""
        if "." in text:
            text, frac = text.split(".", 1)
        t = datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        if frac:
            t = t.replace(microsecond=int((frac + "000000")[:6]))
        return t


def read(data: bytes, i: int = 0) -> tuple[Node, int]:
    start = i
    tag = data[i]
    i += 1
    if tag & 0x1F == 0x1F:
        raise ValueError("high-tag-number form not supported")
    length = data[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    end = i + length
    if end > len(data):
        raise ValueError("truncated DER")
    return Node(tag, data[i:end], data[start:end]), end


def parse(data: bytes) -> Node:
    node, end = read(data, 0)
    if end != len(data):
        raise ValueError("trailing bytes after DER value")
    return node
