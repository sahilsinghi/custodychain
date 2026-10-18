#!/usr/bin/env python3
"""Run the README demo for real and record it as a GIF.

    python scripts/record_demo.py docs/demo.gif      (needs Pillow for the rendering step)

Every command shown in the GIF is executed here in a scratch directory and its real output
is captured; nothing is typed in by hand.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(sys.executable).parent


def main() -> int:
    out_gif = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "demo.gif"
    work = Path(tempfile.mkdtemp(prefix="custody-demo-"))
    env = {**os.environ, "NO_COLOR": "1", "COLUMNS": "118", "CUSTODY_KEY_PASSWORD": "demo-password-not-secret",
           "PATH": f"{BIN}:{os.environ['PATH']}"}
    shutil.copytree(ROOT / "trust", work / "trust")

    def run(cmd: str) -> str:
        p = subprocess.run(cmd, shell=True, cwd=work, env=env, capture_output=True, text=True)
        return (p.stdout + p.stderr).rstrip()

    for actor, role in (("admin", "admin"), ("alice", "analyst"), ("bob", "analyst")):
        run(f"custody keys new {actor} --role {role} -o keys/{actor}.key")
    run("python3 -c \"import os; open('usb.raw','wb').write(os.urandom(24 << 20))\" && chmod a-w usb.raw")

    steps: list[dict] = [{"say": "# CustodyChain: hash -> log -> anchor -> verify, then tamper and verify again", "hold": 1.5}]

    def step(cmd: str, hold: float = 1.6, keep: int | None = None, grep: tuple[str, ...] = ()) -> None:
        text = run(cmd)
        lines = text.splitlines()
        if grep:
            lines = [ln for ln in lines if any(g in ln for g in grep)]
        if keep is not None:
            lines = lines[:keep]
        steps.append({"cmd": cmd, "out": "\n".join(lines), "hold": hold})

    step('custody init case.db --case CASE-0418 --title "Synthetic case" --admin-key keys/admin.key '
         '--member keys/alice.pub --member keys/bob.pub', keep=3)
    step('custody acquire case.db usb.raw --exhibit EX-002 --label "USB stick" --key keys/alice.key --workers 4',
         grep=("acquired", "merkle root", "sha256"))
    step('custody handover case.db EX-002 --from-key keys/alice.key --to-key keys/bob.key --reason locker')
    step("custody anchor case.db --key keys/bob.key --tsa freetsa --tsa digicert", hold=2.0)
    step("custody-verify case.db --tsa-ca trust --evidence EX-002=usb.raw", hold=3.0,
         grep=("[PASS]", "[WARN]", "[FAIL]", "RESULT", "identical"))
    steps.append({"say": "# an insider rewrites the handover reason and flips one bit of the evidence", "hold": 1.8})
    step("sqlite3 case.db \"DROP TRIGGER entries_append_only_update; "
         "UPDATE entries SET body = CAST(replace(CAST(body AS TEXT), 'locker', 'lost') AS BLOB) WHERE seq = 2\"")
    step("chmod u+w usb.raw && python3 -c \"f=open('usb.raw','r+b'); f.seek(9_000_000); b=f.read(1); "
         "f.seek(9_000_000); f.write(bytes([b[0] ^ 1]))\"")
    step("custody-verify case.db --tsa-ca trust --evidence EX-002=usb.raw", hold=6.0,
         grep=("[PASS]", "[FAIL]", "[WARN]", "RESULT", "seq ", "chunk", "anchor "))

    session = work / "session.json"
    session.write_text(json.dumps(steps, indent=1))
    subprocess.run([sys.executable, str(ROOT / "scripts" / "termgif.py"), str(session), str(out_gif),
                    "custodychain demo"], check=True)
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
