"""Draft data for an electronic-evidence certificate under Section 63 of the
Bharatiya Sakshya Adhiniyam, 2023 (BSA).

Section 63(4) requires a certificate, in the form set out in the Schedule,
to accompany electronic records, with a part completed by the person in
charge of the device and a part completed by an expert, including the hash
value(s) of the record and the algorithm used. This module gathers the
technical facts CustodyChain already holds - device details, acquisition
hashes, the custody timeline and TSA-proven times - into a data sheet a
lab can transcribe into its certificate.

It does NOT produce the certificate itself and is not legal advice. The
required wording and format must be confirmed with the lab's legal team
before relying on it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from custodychain.ledger import Ledger

DISCLAIMER = (
    "DRAFT DATA SHEET - NOT A CERTIFICATE. Prepared from the CustodyChain case log to assist in completing "
    "the certificate required by Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023. Confirm the "
    "current prescribed format and wording with your lab's legal team before relying on it."
)


def _exhibit_entry(ledger: Ledger, exhibit_id: str) -> tuple[Any, dict]:
    for e in ledger.entries():
        ex = e.body.get("exhibit") or {}
        if ex.get("id") == exhibit_id:
            return e, ex
    raise KeyError(f"no signed entry records exhibit {exhibit_id}")


def datasheet(ledger: Ledger, exhibit_id: str) -> dict[str, Any]:
    entry, ex = _exhibit_entry(ledger, exhibit_id)
    timeline = []
    for e in ledger.entries():
        d = e.body.get("details") or {}
        if (e.body.get("exhibit") or {}).get("id") == exhibit_id or d.get("exhibit") == exhibit_id:
            timeline.append({"seq": e.seq, "time": e.body["time"], "actor": e.body["actor"], "action": e.body["action"],
                             "witness": (e.body.get("witness") or {}).get("actor"), "note": d.get("note") or d.get("reason")})
    digests = ex.get("digests") or {}
    return {
        "disclaimer": DISCLAIMER,
        "case": ledger.case_id,
        "exhibit": exhibit_id,
        "description": ex.get("label"),
        "part_a_device": {
            "device_description": (ex.get("source") or {}).get("device") or "(enter make, model, serial / IMEI)",
            "file_or_image": (ex.get("source") or {}).get("file"),
            "acquired_by": entry.body["actor"],
            "acquired_at_claimed": entry.body["time"],
            "custody_log_entry": entry.seq,
            "custody_log_genesis": ledger.entries()[0].entry_hash.hex(),
        },
        "part_b_hashes": {
            "MD5": digests.get("md5"),
            "SHA-1": digests.get("sha1"),
            "SHA-256": digests.get("sha256"),
            "Merkle root (RFC 9162, SHA-256 over 4 MiB chunks)": ex.get("merkle_root"),
            "size_bytes": ex.get("size"),
            "E01 embedded MD5 / SHA-1": (f"{(ex.get('ewf') or {}).get('stored_md5')} / {(ex.get('ewf') or {}).get('stored_sha1')}"
                                         if ex.get("ewf") else None),
        },
        "custody_timeline": timeline,
        "independent_verification": "custody-verify <case.db> --tsa-ca trust/ --expect-genesis <genesis> "
                                    f"--evidence {exhibit_id}=<path>",
    }


def write_datasheet(ledger: Ledger, exhibit_id: str, out: Path) -> Path:
    ds = datasheet(ledger, exhibit_id)
    lines = [f"# Section 63 BSA data sheet - {ds['case']} / {ds['exhibit']}", "", f"> {ds['disclaimer']}", "",
             f"**Electronic record:** {ds['description']}", "", "## Part A - device and record (person in charge)", ""]
    lines += [f"- **{k.replace('_', ' ')}:** {v}" for k, v in ds["part_a_device"].items()]
    lines += ["", "## Part B - hash values (expert)", ""]
    lines += [f"- **{k}:** `{v}`" for k, v in ds["part_b_hashes"].items() if v]
    lines += ["", "## Custody of this record", "", "| # | Time (claimed, UTC) | By | Action | Witness | Note |", "|---|---|---|---|---|---|"]
    lines += [f"| {t['seq']} | {t['time']} | {t['actor']} | {t['action']} | {t['witness'] or ''} | {t['note'] or ''} |"
              for t in ds["custody_timeline"]]
    lines += ["", "## Independent verification", "", f"`{ds['independent_verification']}`", ""]
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def annex_flowables(ledger: Ledger, report: dict[str, Any]) -> list[Any]:
    from reportlab.platypus import Paragraph, Spacer

    from custodychain.report import BODY, H2, MONO, SMALL

    out: list[Any] = [Paragraph("Annex - Section 63 BSA data (draft)", H2), Paragraph(DISCLAIMER, SMALL), Spacer(1, 4)]
    for ex in report["exhibits"]:
        if ex.get("parent"):
            continue
        try:
            ds = datasheet(ledger, ex["id"])
        except KeyError:
            continue
        out.append(Paragraph(f"<b>{ex['id']}</b> — {ds['description']}", BODY))
        for k, v in list(ds["part_a_device"].items()) + list(ds["part_b_hashes"].items()):
            if v:
                out.append(Paragraph(f"{k.replace('_', ' ')}: {v}", MONO))
        out.append(Spacer(1, 6))
    return out
