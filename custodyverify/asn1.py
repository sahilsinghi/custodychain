"""A small, strict DER reader (independent of the writer's encoder)."""

from __future__ import annotations

from datetime import datetime, timezone


class ASN1Error(ValueError):
    pass


class TLV:
    __slots__ = ("cls", "constructed", "number", "value", "encoded")

    def __init__(self, cls: int, constructed: bool, number: int, value: bytes, encoded: bytes):
        self.cls = cls
        self.constructed = constructed
        self.number = number
        self.value = value
        self.encoded = encoded

    # tag helpers -------------------------------------------------------
    def is_universal(self, number: int) -> bool:
        return self.cls == 0 and self.number == number

    def is_context(self, number: int) -> bool:
        return self.cls == 2 and self.number == number

    @property
    def items(self) -> list["TLV"]:
        if not self.constructed:
            raise ASN1Error("primitive value has no children")
        return decode_all(self.value)

    # value helpers -----------------------------------------------------
    def integer(self) -> int:
        if not self.is_universal(2):
            raise ASN1Error("expected INTEGER")
        return int.from_bytes(self.value, "big", signed=True)

    def oid(self) -> str:
        if not self.is_universal(6):
            raise ASN1Error("expected OBJECT IDENTIFIER")
        out, acc = [], 0
        for i, byte in enumerate(self.value):
            acc = (acc << 7) | (byte & 0x7F)
            if not byte & 0x80:
                if not out:
                    first = min(acc // 40, 2)
                    out.extend([first, acc - 40 * first])
                else:
                    out.append(acc)
                acc = 0
        return ".".join(str(x) for x in out)

    def octets(self) -> bytes:
        if not self.is_universal(4):
            raise ASN1Error("expected OCTET STRING")
        return self.value

    def bits(self) -> bytes:
        if not self.is_universal(3):
            raise ASN1Error("expected BIT STRING")
        if self.value[0] != 0:
            raise ASN1Error("BIT STRING with unused bits")
        return self.value[1:]

    def boolean(self) -> bool:
        return self.value != b"\x00"

    def time(self) -> datetime:
        text = self.value.decode("ascii")
        if self.is_universal(23):  # UTCTime YYMMDDHHMMSSZ
            yy = int(text[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            return datetime(year, int(text[2:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]),
                            int(text[10:12]), tzinfo=timezone.utc)
        if self.is_universal(24):  # GeneralizedTime YYYYMMDDHHMMSS[.f]Z
            body = text.rstrip("Z")
            micro = 0
            if "." in body:
                body, frac = body.split(".", 1)
                micro = int((frac + "000000")[:6])
            return datetime(int(body[0:4]), int(body[4:6]), int(body[6:8]), int(body[8:10]), int(body[10:12]),
                            int(body[12:14]), micro, tzinfo=timezone.utc)
        raise ASN1Error("expected a time value")

    def text(self) -> str:
        return self.value.decode("utf-8", "replace")


def decode_one(data: bytes, pos: int = 0) -> tuple[TLV, int]:
    if pos >= len(data):
        raise ASN1Error("unexpected end of data")
    start = pos
    first = data[pos]
    pos += 1
    cls, constructed, number = first >> 6, bool(first & 0x20), first & 0x1F
    if number == 0x1F:
        number = 0
        while True:
            b = data[pos]
            pos += 1
            number = (number << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    length = data[pos]
    pos += 1
    if length == 0x80:
        raise ASN1Error("indefinite length is not DER")
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise ASN1Error("length runs past the end of data")
    return TLV(cls, constructed, number, data[pos:end], data[start:end]), end


def decode_all(data: bytes) -> list[TLV]:
    out, pos = [], 0
    while pos < len(data):
        tlv, pos = decode_one(data, pos)
        out.append(tlv)
    return out


def decode(data: bytes) -> TLV:
    tlv, end = decode_one(data, 0)
    if end != len(data):
        raise ASN1Error("trailing data after DER value")
    return tlv
