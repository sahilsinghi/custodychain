"""Read the media stream of an E01 image (independent, minimal implementation).

Walks the section chain, takes the chunk table, inflates zlib chunks and
checks Adler-32 on stored ones. Yields media bytes in fixed-size blocks.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Iterator

MAGIC = b"EVF\t\r\n\xff\x00"


class E01Error(Exception):
    pass


def looks_like_e01(path: Path) -> bool:
    with open(path, "rb") as f:
        return f.read(8) == MAGIC


def _segments(first: Path) -> list[Path]:
    segs = [first]
    if first.suffix.upper() == ".E01":
        n = 2
        while True:
            nxt = first.with_suffix(first.suffix[:2] + f"{n:02d}")
            if not nxt.exists():
                break
            segs.append(nxt)
            n += 1
    return segs


def read_layout(first: Path) -> dict:
    chunks: list[tuple[Path, int, int, bool]] = []
    media_size = chunk_size = 0
    md5 = sha1 = None
    for seg in _segments(first):
        data_len = seg.stat().st_size
        with open(seg, "rb") as f:
            if f.read(8) != MAGIC:
                raise E01Error(f"{seg.name}: missing EVF signature")
            pos, table, sectors_end = 13, [], 0
            while pos + 76 <= data_len:
                f.seek(pos)
                d = f.read(76)
                if zlib.adler32(d[:72]) & 0xFFFFFFFF != struct.unpack("<I", d[72:])[0]:
                    raise E01Error(f"{seg.name}: corrupt section descriptor at {pos}")
                kind = d[:16].split(b"\x00", 1)[0]
                nxt, size = struct.unpack("<QQ", d[16:32])
                if kind in (b"volume", b"disk"):
                    v = f.read(24)
                    spc, bps, nsec = struct.unpack_from("<IIQ", v, 8)
                    chunk_size, media_size = spc * bps, nsec * bps
                elif kind == b"sectors":
                    sectors_end = pos + size
                elif kind == b"table":
                    count, _, base = struct.unpack("<IIQ", f.read(16))
                    f.seek(pos + 76 + 24)
                    for raw in struct.unpack(f"<{count}I", f.read(4 * count)):
                        table.append((base + (raw & 0x7FFFFFFF), bool(raw >> 31)))
                elif kind == b"digest":
                    blob = f.read(36)
                    md5, sha1 = blob[:16].hex(), blob[16:].hex()
                elif kind == b"hash" and md5 is None:
                    md5 = f.read(16).hex()
                if kind == b"done" or nxt in (pos, 0):
                    break
                pos = nxt
            for i, (off, comp) in enumerate(table):
                end = table[i + 1][0] if i + 1 < len(table) else sectors_end
                chunks.append((seg, off, end - off, comp))
    if not chunks:
        raise E01Error("no chunk table")
    return {"chunks": chunks, "media_size": media_size, "chunk_size": chunk_size, "md5": md5, "sha1": sha1}


def media_blocks(first: Path, block: int) -> Iterator[bytes]:
    layout = read_layout(first)
    left = layout["media_size"]
    pending = bytearray()
    handles: dict[Path, object] = {}
    try:
        for seg, off, length, comp in layout["chunks"]:
            fh = handles.get(seg) or open(seg, "rb")
            handles[seg] = fh
            fh.seek(off)
            raw = fh.read(length)
            if comp:
                data = zlib.decompress(raw)
            else:
                data = raw[:-4]
                if zlib.adler32(data) & 0xFFFFFFFF != struct.unpack("<I", raw[-4:])[0]:
                    raise E01Error(f"{seg.name}: chunk at {off} fails its Adler-32 check")
            data = data[:left]
            left -= len(data)
            pending += data
            while len(pending) >= block:
                yield bytes(pending[:block])
                del pending[:block]
        if pending:
            yield bytes(pending)
    finally:
        for fh in handles.values():
            fh.close()
