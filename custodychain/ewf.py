"""Expert Witness (EWF / E01) images: a small writer and a streaming reader.

Real-world E01 files carry the acquisition tool's own MD5 (and SHA-1 in
EnCase 6+ "digest" sections) of the *media*, not of the container. When an
exhibit is an E01, CustodyChain hashes the decoded media, verifies those
embedded hashes against it, and records both alongside its own Merkle root.

The reader is pure Python (zlib + struct) so it works where libewf is not
available or was built without zlib; when ``pyewf`` is importable it is used
as a cross-check. The writer exists for fixtures and demos (single segment,
EnCase-6-style sections: header, volume, sectors, table, table2, digest,
hash, done) and its output is validated against libewf in the test suite.

Format reference: Joachim Metz, "Expert Witness Compression Format (EWF)".
"""

from __future__ import annotations

import hashlib
import struct
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator

EVF_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
SECTION_DESCRIPTOR_SIZE = 76
BYTES_PER_SECTOR = 512
DEFAULT_SECTORS_PER_CHUNK = 64  # 32 KiB chunks, EnCase default


class EwfError(Exception):
    pass


def _adler(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def _descriptor(kind: str, offset: int, size: int, next_offset: int | None = None) -> bytes:
    nxt = offset + size if next_offset is None else next_offset
    body = kind.encode("ascii").ljust(16, b"\x00") + struct.pack("<QQ", nxt, size) + b"\x00" * 40
    return body + struct.pack("<I", _adler(body))


# --------------------------------------------------------------------------
# writer
# --------------------------------------------------------------------------

@dataclass
class EwfMetadata:
    case_number: str = ""
    evidence_number: str = ""
    description: str = ""
    examiner: str = ""
    notes: str = ""
    acquired: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _header_text(meta: EwfMetadata) -> bytes:
    t = meta.acquired
    stamp = f"{t.year} {t.month} {t.day} {t.hour} {t.minute} {t.second}"
    lines = [
        "1",
        "main",
        "c\tn\ta\te\tt\tav\tov\tm\tu\tp",
        "\t".join([meta.case_number, meta.evidence_number, meta.description, meta.examiner, meta.notes,
                   "6.0", "CustodyChain", stamp, stamp, "0"]),
        "",
        "",
    ]
    return "\n".join(lines).encode("ascii", "replace")


def write_e01(source: Path, target: Path, meta: EwfMetadata | None = None, compress: bool = True,
              sectors_per_chunk: int = DEFAULT_SECTORS_PER_CHUNK) -> dict[str, str]:
    """Write ``source`` (a raw image) as a single-segment E01. Returns media hashes."""
    meta = meta or EwfMetadata()
    size = source.stat().st_size
    if size % BYTES_PER_SECTOR:
        raise EwfError("raw image size must be a multiple of 512 bytes")
    chunk_size = sectors_per_chunk * BYTES_PER_SECTOR
    n_chunks = (size + chunk_size - 1) // chunk_size
    md5, sha1 = hashlib.md5(), hashlib.sha1()

    with open(target, "wb") as out:
        out.write(EVF_SIGNATURE + b"\x01" + struct.pack("<H", 1) + b"\x00\x00")
        # header (zlib-compressed header string)
        header = zlib.compress(_header_text(meta))
        off = out.tell()
        out.write(_descriptor("header", off, SECTION_DESCRIPTOR_SIZE + len(header)) + header)
        # volume
        volume = bytearray(1052)
        volume[0] = 0x01  # fixed disk
        struct.pack_into("<IIIQ", volume, 4, n_chunks, sectors_per_chunk, BYTES_PER_SECTOR, size // BYTES_PER_SECTOR)
        volume[36] = 0x01  # media flags: image file
        volume[52] = 0x01 if compress else 0x00
        struct.pack_into("<I", volume, 56, sectors_per_chunk)  # error granularity
        volume[64:80] = uuid.uuid4().bytes
        struct.pack_into("<I", volume, 1048, _adler(bytes(volume[:1048])))
        off = out.tell()
        out.write(_descriptor("volume", off, SECTION_DESCRIPTOR_SIZE + 1052) + bytes(volume))
        # sectors: descriptor placeholder, then chunks
        sectors_off = out.tell()
        out.write(b"\x00" * SECTION_DESCRIPTOR_SIZE)
        offsets: list[int] = []
        with open(source, "rb") as src:
            for _ in range(n_chunks):
                chunk = src.read(chunk_size)
                md5.update(chunk)
                sha1.update(chunk)
                pos = out.tell()
                if compress:
                    packed = zlib.compress(chunk, 6)
                    if len(packed) < len(chunk):
                        out.write(packed)
                        offsets.append(pos | 0x80000000)
                        continue
                out.write(chunk + struct.pack("<I", _adler(chunk)))
                offsets.append(pos)
        end = out.tell()
        out.seek(sectors_off)
        out.write(_descriptor("sectors", sectors_off, end - sectors_off))
        out.seek(end)
        if end >= 0x80000000:
            raise EwfError("fixture writer supports single segments under 2 GiB")
        # table + table2
        entries = struct.pack(f"<{len(offsets)}I", *offsets)
        head = struct.pack("<IIQI", len(offsets), 0, 0, 0)
        table_data = head + struct.pack("<I", _adler(head)) + entries + struct.pack("<I", _adler(entries))
        for kind in ("table", "table2"):
            off = out.tell()
            out.write(_descriptor(kind, off, SECTION_DESCRIPTOR_SIZE + len(table_data)) + table_data)
        # digest (MD5 + SHA-1) and hash (MD5)
        digest = md5.digest() + sha1.digest() + b"\x00" * 40
        digest += struct.pack("<I", _adler(digest))
        off = out.tell()
        out.write(_descriptor("digest", off, SECTION_DESCRIPTOR_SIZE + len(digest)) + digest)
        hsh = md5.digest() + b"\x00" * 16
        hsh += struct.pack("<I", _adler(hsh))
        off = out.tell()
        out.write(_descriptor("hash", off, SECTION_DESCRIPTOR_SIZE + len(hsh)) + hsh)
        off = out.tell()
        out.write(_descriptor("done", off, SECTION_DESCRIPTOR_SIZE, next_offset=off))
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest()}


# --------------------------------------------------------------------------
# reader
# --------------------------------------------------------------------------

@dataclass
class EwfImage:
    paths: list[Path]
    media_size: int
    chunk_size: int
    chunks: list[tuple[int, int, int, bool]]  # (segment index, offset, stored length, compressed)
    stored_md5: str | None
    stored_sha1: str | None
    header: dict[str, str]

    def iter_media(self, block: int) -> Iterator[bytes]:
        """Yield the decoded media in blocks of ``block`` bytes (last may be short)."""
        handles = [open(p, "rb") for p in self.paths]
        try:
            buf = bytearray()
            remaining = self.media_size
            for seg, off, length, compressed in self.chunks:
                fh = handles[seg]
                fh.seek(off)
                raw = fh.read(length)
                if compressed:
                    data = zlib.decompress(raw)
                else:
                    data, stored = raw[:-4], raw[-4:]
                    if struct.unpack("<I", stored)[0] != _adler(data):
                        raise EwfError(f"chunk at segment {seg} offset {off}: Adler-32 mismatch")
                data = data[: min(len(data), remaining)]
                remaining -= len(data)
                buf += data
                while len(buf) >= block:
                    yield bytes(buf[:block])
                    del buf[:block]
            if buf:
                yield bytes(buf)
        finally:
            for fh in handles:
                fh.close()


def segment_paths(first: Path) -> list[Path]:
    """E01, E02, ... E99, EAA ... (only the numeric range is handled)."""
    paths = [first]
    stem, suffix = first.with_suffix(""), first.suffix
    if suffix.upper() == ".E01":
        for n in range(2, 100):
            candidate = stem.with_suffix(f"{suffix[0:2]}{n:02d}")
            if not candidate.exists():
                break
            paths.append(candidate)
    return paths


def _parse_header(raw: bytes) -> dict[str, str]:
    try:
        text = zlib.decompress(raw).decode("utf-8", "replace")
    except zlib.error:
        return {}
    lines = text.replace("\r", "").split("\n")
    if len(lines) < 4:
        return {}
    keys, values = lines[2].split("\t"), lines[3].split("\t")
    names = {"c": "case_number", "n": "evidence_number", "a": "description", "e": "examiner", "t": "notes",
             "av": "acquiry_software_version", "ov": "acquiry_operating_system", "m": "acquiry_date", "u": "system_date"}
    return {names.get(k, k): v for k, v in zip(keys, values)}


def is_ewf(path: Path) -> bool:
    with open(path, "rb") as fh:
        return fh.read(8) == EVF_SIGNATURE


def open_e01(first: Path) -> EwfImage:
    paths = segment_paths(first)
    chunk_size = 0
    media_size = 0
    chunks: list[tuple[int, int, int, bool]] = []
    md5 = sha1 = None
    header: dict[str, str] = {}
    for seg_index, path in enumerate(paths):
        file_size = path.stat().st_size
        with open(path, "rb") as fh:
            if fh.read(8) != EVF_SIGNATURE:
                raise EwfError(f"{path}: not an EWF (E01) file")
            fh.seek(13)
            offset = 13
            seg_chunk_offsets: list[tuple[int, bool]] = []
            sectors_end = 0
            while offset < file_size:
                fh.seek(offset)
                desc = fh.read(SECTION_DESCRIPTOR_SIZE)
                if len(desc) < SECTION_DESCRIPTOR_SIZE:
                    break
                if struct.unpack("<I", desc[72:76])[0] != _adler(desc[:72]):
                    raise EwfError(f"{path}: section descriptor checksum mismatch at offset {offset}")
                kind = desc[:16].rstrip(b"\x00").decode("ascii", "replace")
                next_off, size = struct.unpack("<QQ", desc[16:32])
                data_off = offset + SECTION_DESCRIPTOR_SIZE
                if kind in ("header", "header2") and not header:
                    header = _parse_header(fh.read(size - SECTION_DESCRIPTOR_SIZE))
                elif kind in ("volume", "disk"):
                    vol = fh.read(1052)
                    _, spc, bps, n_sectors = struct.unpack_from("<IIIQ", vol, 4)
                    chunk_size = spc * bps
                    media_size = n_sectors * bps
                elif kind == "sectors":
                    sectors_end = offset + size
                elif kind == "table":
                    head = fh.read(24)
                    count, _, base = struct.unpack_from("<IIQ", head, 0)
                    raw = fh.read(4 * count)
                    for value in struct.unpack(f"<{count}I", raw):
                        seg_chunk_offsets.append((base + (value & 0x7FFFFFFF), bool(value & 0x80000000)))
                elif kind == "digest":
                    data = fh.read(36)
                    md5 = data[:16].hex() if any(data[:16]) else md5
                    sha1 = data[16:36].hex() if any(data[16:36]) else sha1
                elif kind == "hash":
                    data = fh.read(16)
                    md5 = md5 or (data.hex() if any(data) else None)
                if kind == "done" or next_off == offset or next_off == 0:
                    break
                offset = next_off
            for i, (off, compressed) in enumerate(seg_chunk_offsets):
                end = seg_chunk_offsets[i + 1][0] if i + 1 < len(seg_chunk_offsets) else sectors_end
                chunks.append((seg_index, off, end - off, compressed))
    if not chunk_size or not chunks:
        raise EwfError(f"{first}: no volume or table section found")
    return EwfImage(paths, media_size, chunk_size, chunks, md5, sha1, header)


def verify_embedded_hashes(image: EwfImage, block: int = 4 << 20) -> dict[str, object]:
    md5, sha1 = hashlib.md5(), hashlib.sha1()
    for data in image.iter_media(block):
        md5.update(data)
        sha1.update(data)
    out: dict[str, object] = {"computed_md5": md5.hexdigest(), "computed_sha1": sha1.hexdigest(),
                              "stored_md5": image.stored_md5, "stored_sha1": image.stored_sha1}
    out["md5_match"] = None if image.stored_md5 is None else image.stored_md5 == out["computed_md5"]
    out["sha1_match"] = None if image.stored_sha1 is None else image.stored_sha1 == out["computed_sha1"]
    return out


def libewf_cross_check(first: Path) -> dict[str, object] | None:
    """Read the same image with libewf (pyewf) when available."""
    try:
        import pyewf  # type: ignore
    except ImportError:
        return None
    handle = pyewf.handle()
    try:
        handle.open([str(p) for p in segment_paths(first)])
        md5 = hashlib.md5()
        remaining = handle.get_media_size()
        while remaining:
            data = handle.read_buffer(min(remaining, 4 << 20))
            if not data:
                break
            md5.update(data)
            remaining -= len(data)
        return {"media_size": handle.get_media_size(), "md5": md5.hexdigest(),
                "stored": handle.get_hash_values(), "reader": f"libewf {pyewf.get_version()}"}
    except Exception as exc:  # noqa: BLE001 - libewf errors are informational here
        return {"error": str(exc)}
    finally:
        try:
            handle.close()
        except Exception:  # noqa: BLE001
            pass
