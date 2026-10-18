"""Render the verifier's JSON as a printable verification report (PDF).

The PDF is presentation only. It is produced from the independent
verifier's output and contains the commands to re-run that verification,
so a reader never has to trust this renderer.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

INK = colors.HexColor("#1b1f24")
MUTED = colors.HexColor("#5b6470")
LINE = colors.HexColor("#d8dbe0")
PASS = colors.HexColor("#15803d")
FAIL = colors.HexColor("#b91c1c")
WARN = colors.HexColor("#a16207")
HEAD = colors.HexColor("#1e3a8a")
STATUS_COLOR = {"pass": PASS, "fail": FAIL, "warn": WARN, "skip": MUTED}

_styles = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_styles["Title"], fontSize=18, leading=22, alignment=TA_LEFT, textColor=INK, spaceAfter=4)
H2 = ParagraphStyle("h2", parent=_styles["Heading2"], fontSize=12.5, leading=16, textColor=HEAD, spaceBefore=10, spaceAfter=5)
BODY = ParagraphStyle("body", parent=_styles["BodyText"], fontSize=8.6, leading=11, textColor=INK)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=7.4, leading=9.2)
MONO = ParagraphStyle("mono", parent=SMALL, fontName="Courier", fontSize=6.9, leading=8.4)
CELL = ParagraphStyle("cell", parent=SMALL)


def _p(text: Any, style: ParagraphStyle = CELL) -> Paragraph:
    s = "" if text is None else str(text)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(s, style)


def _status(st: str) -> Paragraph:
    color = STATUS_COLOR.get(st, MUTED).hexval()[2:]
    return Paragraph(f'<font color="#{color}"><b>{st.upper()}</b></font>', CELL)


def _table(rows: list[list[Any]], widths: list[float], header: bool = True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.3, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f6"))]
    t.setStyle(TableStyle(style))
    return t


def _size(n: Any) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:,} B" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return str(n)


def _short_time(text: str | None) -> str:
    if not text:
        return "—"
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    return t.strftime("%Y-%m-%d %H:%M:%S") + "Z"


def _rel(path: str) -> str:
    """Show paths relative to the working directory so reports don't leak local layout."""
    import os

    try:
        rel = os.path.relpath(path)
    except ValueError:
        return path
    return rel if not rel.startswith("../..") else Path(path).name


def render_pdf(report: dict[str, Any], out: Path, case_title: str = "", annex: list[Any] | None = None) -> Path:
    doc = SimpleDocTemplate(str(out), pagesize=landscape(A4), leftMargin=14 * mm, rightMargin=14 * mm,
                            topMargin=12 * mm, bottomMargin=13 * mm,
                            title=f"Chain-of-custody verification {report['database'].get('case_id')}",
                            author="custodyverify")
    width = landscape(A4)[0] - 28 * mm
    story: list[Any] = []
    db = report["database"]
    result = report["result"]
    story.append(Paragraph("Chain-of-Custody Verification Report", H1))
    story.append(Paragraph(f"Case <b>{db.get('case_id')}</b>{(' — ' + case_title) if case_title else ''}", BODY))
    color = STATUS_COLOR.get(result, MUTED).hexval()[2:]
    story.append(Spacer(1, 4))
    banner = Table([[Paragraph(f'<font color="#ffffff" size="13"><b>RESULT: {result.upper()}</b></font>', BODY),
                     Paragraph(f'<font color="#ffffff">{sum(1 for c in report["checks"] if c["status"] == "pass")} of '
                               f'{len(report["checks"])} checks passed · {report["log_size"]} log entries · '
                               f'{len(report["exhibits"])} exhibits · {len(report["anchors"])} timestamps</font>', BODY)]],
                   colWidths=[60 * mm, width - 60 * mm])
    banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#" + color)),
                                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 6),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(banner)
    story.append(Spacer(1, 6))
    meta_rows = [
        ["Verifier", f"{report['verifier']} {report['version']} (independent, standard-library only)"],
        ["Generated", report["generated"]],
        ["Case database", f"{_rel(db.get('path'))} · SQLite integrity: {db.get('sqlite_integrity')}"],
        ["Database SHA-256", "; ".join(f"{k}: {v}" for k, v in db.get("sha256", {}).items())],
        ["Genesis entry hash", report.get("genesis")],
        ["Log Merkle root", f"{report.get('log_root')} (RFC 9162, {report['log_size']} leaves)"],
        ["Trusted TSA roots", ", ".join(_rel(p) for p in report["trust"]["ca_bundles"]) or "none supplied"],
    ]
    story.append(_table([[_p(k, SMALL), _p(v, MONO if "hash" in k.lower() or "root" in k.lower() or "SHA" in k else SMALL)]
                         for k, v in meta_rows], [42 * mm, width - 42 * mm], header=False))

    story.append(Paragraph("1. Verification checks", H2))
    rows = [[_p("Check"), _p("Result"), _p("Detail and findings")]]
    for c in report["checks"]:
        findings = "<br/>".join(f.replace("&", "&amp;").replace("<", "&lt;") for f in c["findings"][:12])
        if len(c["findings"]) > 12:
            findings += f"<br/>… {len(c['findings']) - 12} more (see JSON report)"
        detail = c["detail"].replace("&", "&amp;").replace("<", "&lt;")
        text = "<br/>".join(x for x in (detail, findings) if x)
        rows.append([_p(c["title"]), _status(c["status"]), Paragraph(text, CELL)])
    story.append(_table(rows, [70 * mm, 17 * mm, width - 87 * mm]))

    story.append(Paragraph("2. Exhibits", H2))
    rows = [[_p(h) for h in ("ID", "Description", "Type", "Size", "Chunks", "Merkle root / SHA-256 / MD5 / SHA-1", "Source checks")]]
    for ex in report["exhibits"]:
        d = ex.get("digests") or {}
        hashes = (f"root {ex.get('merkle_root')}<br/>sha256 {d.get('sha256', '—')}<br/>md5 {d.get('md5', '—')}"
                  f"<br/>sha1 {d.get('sha1', '—')}")
        checks = []
        if ex.get("parent"):
            checks.append(f"derived from {ex['parent']}")
        if ex.get("ewf"):
            e = ex["ewf"]
            checks.append(f"E01 embedded MD5 match: {e.get('md5_match')}, SHA-1 match: {e.get('sha1_match')}")
        if ex.get("evidence_rehashed"):
            bad = ex.get("failing_chunks")
            checks.append("re-hashed now: " + ("IDENTICAL" if not bad else f"{len(bad)} chunk(s) differ: {bad[:8]}"))
        else:
            checks.append("not re-hashed in this run")
        rows.append([_p(ex["id"]), _p(ex.get("label")), _p(ex.get("kind")), _p(_size(ex.get("size"))),
                     _p(ex.get("leaves")), Paragraph(hashes, MONO), _p("; ".join(checks))])
    story.append(_table(rows, [20 * mm, 40 * mm, 11 * mm, 18 * mm, 12 * mm, 112 * mm, width - 213 * mm]))

    story.append(PageBreak())
    story.append(Paragraph("3. Custody timeline", H2))
    story.append(Paragraph("“Claimed” is the analyst workstation clock. The provable window comes from RFC 3161 "
                           "timestamps: an entry existed before the first timestamp covering it and was written after "
                           "any timestamp logged before it.", SMALL))
    story.append(Spacer(1, 3))
    rows = [[_p(h) for h in ("#", "Claimed time (UTC)", "Provable window (UTC)", "Actor", "Action", "Witness", "Details", "Signature")]]
    for e in report["entries"]:
        window = f"after&nbsp;&nbsp;{_short_time(e.get('provable_after'))}<br/>before {_short_time(e.get('provable_before'))}"
        sig = e.get("signature", "invalid")
        rows.append([_p(e["seq"]), _p(_short_time(e.get("time_claimed"))), Paragraph(window, CELL), _p(e.get("actor")),
                     _p(e.get("action")), _p(e.get("witness") or ""), _p(e.get("summary")),
                     _status("pass" if sig == "valid" else "fail")])
    story.append(_table(rows, [9 * mm, 31 * mm, 40 * mm, 18 * mm, 18 * mm, 14 * mm, width - 147 * mm, 17 * mm]))

    story.append(Paragraph("4. Trusted timestamps", H2))
    rows = [[_p(h) for h in ("TSA", "Entries covered", "genTime (UTC)", "Serial", "Certificate chain", "Status")]]
    for a in report["anchors"]:
        chain = " → ".join(a.get("chain") or [])
        status = a.get("status", "")
        rows.append([_p(a.get("tsa")), _p(a.get("tree_size")), _p(_short_time(a.get("gen_time"))),
                     Paragraph(str(a.get("serial") or "—"), MONO), _p(chain or "; ".join(a.get("problems") or [])),
                     _status("pass" if status == "valid" else "fail")])
    story.append(_table(rows, [24 * mm, 20 * mm, 32 * mm, 40 * mm, width - 133 * mm, 17 * mm]))
    story.append(Paragraph("Certificate revocation (CRL/OCSP) is not checked: the verifier runs offline. "
                           "Timestamps are validated as of their genTime.", SMALL))

    story.append(Paragraph("5. Analyst keys", H2))
    rows = [[_p(h) for h in ("Analyst", "Role", "Key fingerprint", "Added at", "Revoked")]]
    for m in report["roster"]:
        rev = m.get("revocation") or {}
        revoked = "" if m.get("revoked_seq") is None else f"seq {m['revoked_seq']} ({rev.get('reason')}" + (
            f", compromised since seq {rev['compromised_since_seq']})" if rev.get("compromised_since_seq") is not None else ")")
        rows.append([_p(m.get("actor")), _p(m.get("role")), Paragraph(m.get("key_id", ""), MONO),
                     _p(f"seq {m.get('added_seq')}"), _p(revoked)])
    story.append(_table(rows, [35 * mm, 20 * mm, 90 * mm, 25 * mm, width - 170 * mm]))

    story.append(Paragraph("6. Re-running this verification", H2))
    cmd = f"custody-verify {_rel(db.get('path'))} --tsa-ca trust/ --expect-genesis {report.get('genesis')}"
    for ex in report["exhibits"]:
        if ex.get("evidence_rehashed"):
            cmd += f" --evidence {ex['id']}=<path to evidence>"
    story.append(KeepTogether([
        Paragraph("Anyone can repeat every check above with the independent verifier, which uses only the Python "
                  "standard library (its own DER parser, Ed25519, RSA and ECDSA code) and never writes to the case file:", BODY),
        Spacer(1, 3), Paragraph(cmd.replace("<", "&lt;").replace(">", "&gt;"), MONO), Spacer(1, 3),
        Paragraph("What a PASS means: no entry was edited, removed or reordered after it was written; every entry is "
                  "signed by the analyst named in it with a key the case roster authorised at that time; evidence "
                  "that was re-hashed is bit-for-bit what was recorded; and the log existed in this state no later "
                  "than the TSA times shown. What it does not mean: that the original acquisition was forensically "
                  "sound, or that analysts kept their keys secret.", SMALL),
    ]))
    if annex:
        story.append(PageBreak())
        story.extend(annex)

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(14 * mm, 7 * mm, f"Case {db.get('case_id')} · genesis {str(report.get('genesis'))[:24]}… · "
                                           f"verified {report['generated']}")
        canvas.drawRightString(landscape(A4)[0] - 14 * mm, 7 * mm, f"page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return out


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")
