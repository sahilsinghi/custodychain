"""``custody``: the analyst-facing command line."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn, TransferSpeedColumn
from rich.table import Table

from custodychain import __version__, anchor, keys
from custodychain.hasher import CHUNK_SIZE, hash_evidence, readonly_status
from custodychain.ledger import Ledger, LedgerError

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Tamper-evident chain of custody: Merkle-hashed evidence, signed hash-chained log, RFC 3161 anchors.")
keys_app = typer.Typer(no_args_is_help=True, help="Analyst signing keys and the case roster.")
prove_app = typer.Typer(no_args_is_help=True, help="Inclusion and consistency proofs.")
tsa_app = typer.Typer(no_args_is_help=True, help="A local RFC 3161 TSA for tests and air-gapped labs.")
app.add_typer(keys_app, name="keys")
app.add_typer(prove_app, name="prove")
app.add_typer(tsa_app, name="tsa")
console = Console()


def _fail(msg: str) -> None:
    console.print(f"[bold red]error:[/] {msg}")
    raise typer.Exit(2)


def _ledger(db: Path) -> Ledger:
    try:
        return Ledger(db)
    except LedgerError as exc:
        _fail(str(exc))
        raise


def _progress() -> Progress:
    return Progress(TextColumn("[bold]{task.description}"), BarColumn(), TransferSpeedColumn(),
                    TimeRemainingColumn(), console=console, transient=True)


# ---------------------------------------------------------------- keys
@keys_app.command("new")
def keys_new(actor: str, out: Path = typer.Option(..., "--out", "-o"),
             role: str = typer.Option("analyst", help="analyst or admin")):
    """Create an Ed25519 key (password-protected) and its .pub file."""
    if role not in ("analyst", "admin"):
        _fail("role must be analyst or admin")
    signer = keys.generate(actor, role, out)
    console.print(f"created {out} and {out.with_suffix('.pub')}  [dim]{signer.key_id}[/]")


@keys_app.command("add")
def keys_add(db: Path, pub: Path, admin_key: Path = typer.Option(..., "--admin-key"), note: str = ""):
    """Add an analyst's public key to the case roster (admin-signed)."""
    ledger = _ledger(db)
    try:
        e = ledger.add_key(keys.load(admin_key), keys.load_public(pub), note)
    except LedgerError as exc:
        _fail(str(exc))
    console.print(f"seq {e.seq}: key_add {keys.load_public(pub).key_id}")


@keys_app.command("revoke")
def keys_revoke(db: Path, key_id: str, reason: str = typer.Option(..., help="lost | compromised | rotated | left"),
                admin_key: Path = typer.Option(..., "--admin-key"),
                compromised_since: Optional[int] = typer.Option(None, help="entries signed from this seq on are untrusted")):
    """Revoke a key. Revocation is not retroactive unless --compromised-since is given."""
    ledger = _ledger(db)
    try:
        e = ledger.revoke_key(keys.load(admin_key), key_id, reason, compromised_since)
    except LedgerError as exc:
        _fail(str(exc))
    console.print(f"seq {e.seq}: key_revoke {key_id} ({reason})")


@keys_app.command("list")
def keys_list(db: Path):
    t = Table("actor", "role", "key id", "active")
    for m in _ledger(db).roster().values():
        t.add_row(m["actor"], m["role"], m["key_id"], "yes" if m["active"] else "[red]revoked[/]")
    console.print(t)


# ---------------------------------------------------------------- case
@app.command()
def init(db: Path, case: str = typer.Option(..., "--case"), title: str = typer.Option(..., "--title"),
         admin_key: Path = typer.Option(..., "--admin-key"),
         member: List[Path] = typer.Option([], "--member", help="public key files of the analysts on the case")):
    """Open a case: create the database and sign the genesis entry with the key roster."""
    try:
        ledger = Ledger.create(db, case, title, keys.load(admin_key), [keys.load_public(p) for p in member])
    except LedgerError as exc:
        _fail(str(exc))
    genesis = ledger.entries()[0].entry_hash.hex()
    console.print(f"opened case [bold]{case}[/] in {db}")
    console.print(f"genesis [bold]{genesis}[/]")
    console.print("[dim]Record the genesis hash in the case paperwork: verifiers pin it with --expect-genesis.[/]")


def _hash_into(ledger: Ledger, evidence: Path, chunk_mib: int, alg: str, workers: int, label: str,
               digests: tuple[str, ...] = ("sha256", "sha1", "md5")):
    from custodychain import ewf

    chunk = chunk_mib * 1024 * 1024
    with _progress() as prog:
        task = prog.add_task(f"hashing {label}", total=evidence.stat().st_size)

        def progress(done, total):
            prog.update(task, completed=done, total=total)

        if ewf.is_ewf(evidence):
            return hash_evidence(evidence, chunk_size=chunk, alg=alg, progress=progress)
        job_id, done_leaves = ledger.job_for(evidence, chunk, alg)
        if done_leaves:
            console.print(f"[yellow]resuming[/] previous run: {len(done_leaves)} chunks already hashed")
        result = hash_evidence(evidence, chunk_size=chunk, alg=alg, workers=workers, existing_leaves=done_leaves,
                               digests=digests,
                               on_leaves=lambda first, new: ledger.checkpoint_leaves(job_id, first, new),
                               progress=progress)
        ledger.finish_job(job_id)
        return result


@app.command()
def acquire(db: Path, evidence: Path, exhibit: str = typer.Option(..., "--exhibit"),
            label: str = typer.Option(..., "--label"), key: Path = typer.Option(..., "--key"),
            device: str = typer.Option("", help="source device description (make, model, serial)"),
            workers: int = typer.Option(max(1, (os.cpu_count() or 2) - 1), help="hashing processes"),
            alg: str = typer.Option("sha256", help="leaf hash: sha256 or blake3"),
            chunk_mib: int = typer.Option(CHUNK_SIZE // (1 << 20), help="leaf size in MiB"),
            require_readonly: bool = typer.Option(False, help="refuse evidence that is writable by this user"),
            digests: str = typer.Option("sha256,sha1,md5", help="whole-file digests to record ('none' to skip)")):
    """Hash an evidence file (raw or E01) into a Merkle tree and log its acquisition."""
    ledger = _ledger(db)
    signer = keys.load(key)
    ro = readonly_status(evidence)
    if ro["file_writable_by_us"] and not ro["mount_read_only"]:
        msg = f"{evidence} is writable. Work from a write-blocked or read-only copy (chmod a-w, or mount read-only)."
        if require_readonly:
            _fail(msg)
        console.print(f"[yellow]warning:[/] {msg}")
    names = () if digests.strip().lower() == "none" else tuple(d.strip() for d in digests.split(",") if d.strip())
    result = _hash_into(ledger, evidence, chunk_mib, alg, workers, exhibit, names)
    source = {"file": evidence.name, "device": device, "readonly": ro}
    try:
        e = ledger.record_exhibit(signer, "acquire", exhibit, label, result, source=source)
    except LedgerError as exc:
        _fail(str(exc))
    console.print(f"seq {e.seq}: acquired [bold]{exhibit}[/] {result.size:,} bytes in {len(result.leaves)} chunks "
                  f"({result.gbps:.2f} GB/s, {result.workers} worker(s))")
    console.print(f"  merkle root {result.root.hex()}")
    for name, value in result.digests.items():
        console.print(f"  {name:6s} {value}")
    if result.ewf:
        ew = result.ewf
        console.print(f"  E01 embedded MD5 match: {ew['md5_match']}  SHA-1 match: {ew['sha1_match']}"
                      + (f"  (libewf agrees: {ew['libewf'].get('agrees')})" if ew.get("libewf") else ""))


@app.command()
def copy(db: Path, exhibit: str, copy_path: Path, as_: str = typer.Option(..., "--as"),
         key: Path = typer.Option(..., "--key"), workers: int = typer.Option(max(1, (os.cpu_count() or 2) - 1))):
    """Hash a working copy and log it. Refuses copies that differ from the original."""
    ledger = _ledger(db)
    parent = ledger.exhibit(exhibit)
    if parent is None:
        _fail(f"no exhibit {exhibit}")
    result = _hash_into(ledger, copy_path, parent["chunk_size"] // (1 << 20), parent["alg"], workers, as_)
    if result.root != parent["merkle_root"]:
        _fail(f"copy differs from {exhibit}: root {result.root.hex()} != {parent['merkle_root'].hex()}")
    e = ledger.record_exhibit(keys.load(key), "copy", as_, f"working copy of {exhibit}", result, parent=exhibit,
                              source={"file": copy_path.name})
    console.print(f"seq {e.seq}: {as_} is a verified bit-for-bit copy of {exhibit}")


@app.command()
def export(db: Path, exhibit: str, artefact: Path, as_: str = typer.Option(..., "--as"),
           label: str = typer.Option(..., "--label"), key: Path = typer.Option(..., "--key")):
    """Log an artefact extracted from an exhibit (a derived exhibit with its own hashes)."""
    ledger = _ledger(db)
    if ledger.exhibit(exhibit) is None:
        _fail(f"no exhibit {exhibit}")
    result = _hash_into(ledger, artefact, CHUNK_SIZE // (1 << 20), "sha256", 1, as_)
    e = ledger.record_exhibit(keys.load(key), "export", as_, label, result, parent=exhibit,
                              source={"file": artefact.name})
    console.print(f"seq {e.seq}: exported {as_} from {exhibit} ({result.size:,} bytes)")


@app.command("log-action")
def log_action(db: Path, action: str, key: Path = typer.Option(..., "--key"),
               exhibit: Optional[str] = typer.Option(None), note: str = typer.Option("", "--note")):
    """Log mount / analyze / verify / note / seal actions."""
    if action not in ("mount", "analyze", "verify", "note", "seal"):
        _fail("action must be mount, analyze, verify, note or seal")
    ledger = _ledger(db)
    details = {"note": note}
    if exhibit:
        if ledger.exhibit(exhibit) is None:
            _fail(f"no exhibit {exhibit}")
        details["exhibit"] = exhibit
    try:
        e = ledger.append(keys.load(key), action, details=details)
    except LedgerError as exc:
        _fail(str(exc))
    console.print(f"seq {e.seq}: {action} {exhibit or ''} {note}")


@app.command()
def handover(db: Path, exhibit: str, from_key: Path = typer.Option(..., "--from-key"),
             to_key: Path = typer.Option(..., "--to-key"), reason: str = typer.Option("", "--reason")):
    """Hand an exhibit to another analyst; both sign (witness co-signature)."""
    ledger = _ledger(db)
    if ledger.exhibit(exhibit) is None:
        _fail(f"no exhibit {exhibit}")
    giver, receiver = keys.load(from_key), keys.load(to_key)
    try:
        e = ledger.append(giver, "handover", witness=receiver,
                          details={"exhibit": exhibit, "from": giver.actor, "to": receiver.actor, "reason": reason})
    except LedgerError as exc:
        _fail(str(exc))
    console.print(f"seq {e.seq}: {exhibit} handed from {giver.actor} to {receiver.actor} (co-signed)")


@app.command("anchor")
def anchor_cmd(db: Path, key: Path = typer.Option(..., "--key"),
               tsa: List[str] = typer.Option(list(anchor.DEFAULT_TSAS), "--tsa", help="freetsa, digicert, sectigo, globalsign or NAME=URL")):
    """Timestamp the current log root with one or more RFC 3161 TSAs."""
    ledger = _ledger(db)
    targets = []
    for t in tsa:
        if "=" in t:
            name, url = t.split("=", 1)
        elif t in anchor.PUBLIC_TSAS:
            name, url = t, anchor.PUBLIC_TSAS[t]
        else:
            _fail(f"unknown TSA {t!r}")
        targets.append((name, url))
    try:
        e, errors = ledger.anchor(keys.load(key), targets)
    except LedgerError as exc:
        _fail(str(exc))
    d = e.body["details"]
    console.print(f"seq {e.seq}: anchored {d['tree_size']} entries, root {d['root'][:16]}…")
    for tok in d["tokens"]:
        console.print(f"  {tok['tsa']:10s} {tok['gen_time']}  serial {tok['serial']}")
    for err in errors:
        console.print(f"  [yellow]{err}[/]")


@app.command("log")
def show_log(db: Path):
    """Show the custody log."""
    t = Table("seq", "time (claimed)", "actor", "action", "exhibit", "details", show_lines=False)
    for e in _ledger(db).entries():
        b = e.body
        ex = (b.get("exhibit") or {}).get("id") or (b.get("details") or {}).get("exhibit") or ""
        d = b.get("details") or {}
        info = d.get("note") or d.get("reason") or (f"root {d['root'][:12]}… ({d['tree_size']})" if "root" in d else "")
        if b["action"] == "handover":
            info = f"{d.get('from')} → {d.get('to')} (witness signed) {d.get('reason', '')}"
        t.add_row(str(e.seq), b["time"][:19], b["actor"], b["action"], ex, info)
    console.print(t)


@app.command()
def checkpoint(db: Path, out: Path = typer.Option(..., "--out", "-o")):
    """Export the current tree size, root and timestamps (give it to the other side)."""
    cp = _ledger(db).checkpoint()
    out.write_text(json.dumps(cp, indent=2) + "\n")
    console.print(f"checkpoint at size {cp['tree_size']} → {out}  root {cp['root'][:16]}…")


# ---------------------------------------------------------------- proofs
@prove_app.command("chunk")
def prove_chunk(db: Path, exhibit: str, index: int, out: Optional[Path] = None):
    """Inclusion proof that one evidence chunk is part of an exhibit's signed root."""
    proof = _ledger(db).chunk_inclusion(exhibit, index)
    text = json.dumps(proof, indent=2)
    out.write_text(text + "\n") if out else console.print_json(text)


@prove_app.command("entry")
def prove_entry(db: Path, seq: int, size: Optional[int] = None, out: Optional[Path] = None):
    """Inclusion proof that a log entry is in the (anchored) log root."""
    proof = _ledger(db).entry_inclusion(seq, size)
    text = json.dumps(proof, indent=2)
    out.write_text(text + "\n") if out else console.print_json(text)


@prove_app.command("consistency")
def prove_consistency(db: Path, from_: Path = typer.Option(..., "--from", help="earlier checkpoint JSON"),
                      out: Path = typer.Option(..., "--out", "-o")):
    """RFC 9162 consistency proof: today's log is an append-only extension of the checkpoint."""
    cp = json.loads(from_.read_text())
    proof = _ledger(db).consistency(int(cp["tree_size"]))
    if proof["old_root"] != cp["root"]:
        console.print("[bold red]the log's first entries no longer match this checkpoint: history was rewritten[/]")
    out.write_text(json.dumps(proof, indent=2) + "\n")
    console.print(f"consistency proof {cp['tree_size']} → {proof['new_size']} ({len(proof['proof'])} hashes) → {out}")


# ---------------------------------------------------------------- verification
@app.command()
def verify(db: Path, evidence: List[str] = typer.Option([], "--evidence", help="EXHIBIT=PATH to re-hash"),
           tsa_ca: List[Path] = typer.Option([], "--tsa-ca", help="trusted TSA root PEM file or directory"),
           expect_genesis: Optional[str] = typer.Option(None, "--expect-genesis"),
           checkpoint_file: List[Path] = typer.Option([], "--checkpoint"),
           pdf: Optional[Path] = typer.Option(None, "--pdf"), json_out: Optional[Path] = typer.Option(None, "--json"),
           bsa63: bool = typer.Option(False, help="append the BSA s.63 certificate data annex to the PDF")):
    """Run the independent verifier and print / render its report."""
    from custodyverify.check import CaseVerifier
    from custodyverify.cli import print_report

    ev = {}
    for pair in evidence:
        k, _, v = pair.partition("=")
        ev[k] = Path(v)
    report = CaseVerifier(db, ev, tsa_ca, expect_genesis, checkpoint_file).run()
    print_report(report)
    if json_out:
        json_out.write_text(json.dumps(report, indent=2) + "\n")
    if pdf:
        from custodychain.report import render_pdf

        title = ""
        annex = None
        try:
            ledger = Ledger(db)
            title = (ledger.entries()[0].body.get("details") or {}).get("title", "")
            if bsa63:
                from custodychain.bsa63 import annex_flowables

                annex = annex_flowables(ledger, report)
        except LedgerError:
            pass
        render_pdf(report, pdf, case_title=title, annex=annex)
        console.print(f"PDF report → {pdf}")
    raise typer.Exit(1 if report["result"] == "fail" else 0)


@app.command()
def report(json_file: Path, pdf: Path = typer.Option(..., "--pdf")):
    """Render an existing verifier JSON report as PDF."""
    from custodychain.report import render_pdf

    render_pdf(json.loads(json_file.read_text()), pdf)
    console.print(f"PDF report → {pdf}")


# ---------------------------------------------------------------- local TSA
@tsa_app.command("init")
def tsa_init(directory: Path, kind: str = typer.Option("ec", help="ec or rsa")):
    from custodychain.testtsa import TestTSA

    TestTSA.create(kind).save(directory)
    console.print(f"local TSA in {directory} (trust {directory / 'ca.pem'} to verify its tokens)")


@tsa_app.command("serve")
def tsa_serve(directory: Path, port: int = 3161):
    import time

    from custodychain.testtsa import TestTSA, serve

    serve(TestTSA.load(directory), port=port)
    console.print(f"local TSA listening on http://127.0.0.1:{port}/  (Ctrl-C to stop)")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------- misc
@app.command()
def bench(size_gib: float = typer.Option(2.0), out: Optional[Path] = typer.Option(None),
          workers: str = typer.Option("1,2,4,8"), scratch: Path = typer.Option(Path("."), help="where to write the test file")):
    """Benchmark leaf hashing: SHA-256 vs BLAKE3, single vs multi-process."""
    from custodychain.bench import run_bench

    run_bench(size_gib, [int(w) for w in workers.split(",")], scratch, out, console)


@app.command("bsa63")
def bsa63_cmd(db: Path, exhibit: str, out: Path = typer.Option(..., "--out", "-o")):
    """Draft the hash/device data for a Bharatiya Sakshya Adhiniyam s.63 certificate."""
    from custodychain.bsa63 import write_datasheet

    write_datasheet(_ledger(db), exhibit, out)
    console.print(f"draft data sheet → {out}  [yellow](verify the required format with your lab's legal team)[/]")


@app.command()
def version():
    console.print(f"custodychain {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
