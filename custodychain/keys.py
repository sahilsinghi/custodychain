"""Per-analyst Ed25519 signing keys.

MVP storage is a password-protected PKCS#8 PEM (scrypt KDF via
``cryptography``'s BestAvailableEncryption). The public half is shared as a
small JSON ``.pub`` file and pinned in the case roster by fingerprint.

A key ID is ``ed25519:`` + the first 16 bytes of SHA-256 over the raw 32-byte
public key, short enough to read out over the phone when a key is reported
lost.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PASSWORD_ENV = "CUSTODY_KEY_PASSWORD"


def key_id(public_raw: bytes) -> str:
    return "ed25519:" + hashlib.sha256(public_raw).digest()[:16].hex()


@dataclass
class PublicKey:
    actor: str
    role: str
    raw: bytes

    @property
    def key_id(self) -> str:
        return key_id(self.raw)

    def to_json(self) -> dict:
        return {"actor": self.actor, "role": self.role, "key_id": self.key_id,
                "public_key": base64.b64encode(self.raw).decode()}

    @classmethod
    def from_json(cls, data: dict) -> "PublicKey":
        pk = cls(actor=data["actor"], role=data.get("role", "analyst"), raw=base64.b64decode(data["public_key"]))
        if "key_id" in data and data["key_id"] != pk.key_id:
            raise ValueError("public key file: key_id does not match the key")
        return pk


@dataclass
class Signer:
    actor: str
    role: str
    private: Ed25519PrivateKey

    @property
    def public_raw(self) -> bytes:
        return self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def key_id(self) -> str:
        return key_id(self.public_raw)

    @property
    def public(self) -> PublicKey:
        return PublicKey(self.actor, self.role, self.public_raw)

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def _env_name(path: Path | None) -> str | None:
    if path is None:
        return None
    stem = "".join(ch if ch.isalnum() else "_" for ch in Path(path).stem).upper()
    return f"{PASSWORD_ENV}_{stem}"


def _password(password: str | None, confirm: bool = False, prompt: str = "Key password: ",
              path: Path | None = None) -> bytes:
    """Explicit argument, then CUSTODY_KEY_PASSWORD_<KEYFILE>, then CUSTODY_KEY_PASSWORD, then a prompt."""
    if password is None and _env_name(path):
        password = os.environ.get(_env_name(path))
    if password is None:
        password = os.environ.get(PASSWORD_ENV)
    if password is None:
        password = getpass.getpass(prompt)
        if confirm and getpass.getpass("Repeat password: ") != password:
            raise ValueError("passwords do not match")
    if len(password) < 8:
        raise ValueError("key password must be at least 8 characters")
    return password.encode("utf-8")


def generate(actor: str, role: str, out: Path, password: str | None = None) -> Signer:
    """Create ``out`` (encrypted private key) and ``out.pub`` (public JSON)."""
    if out.exists():
        raise FileExistsError(f"{out} already exists; refusing to overwrite a key")
    signer = Signer(actor, role, Ed25519PrivateKey.generate())
    pem = signer.private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(_password(password, confirm=True, path=out)),
    )
    meta = f"# custodychain key\n# actor: {actor}\n# role: {role}\n# key_id: {signer.key_id}\n".encode()
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(meta + pem)
    pub_path = out.with_suffix(out.suffix + ".pub") if out.suffix != ".key" else out.with_suffix(".pub")
    pub_path.write_text(json.dumps(signer.public.to_json(), indent=2) + "\n", encoding="utf-8")
    return signer


def load(path: Path, password: str | None = None) -> Signer:
    text = path.read_bytes()
    actor = role = ""
    for line in text.decode("utf-8", "replace").splitlines():
        if line.startswith("# actor:"):
            actor = line.split(":", 1)[1].strip()
        elif line.startswith("# role:"):
            role = line.split(":", 1)[1].strip()
    pem_start = text.index(b"-----BEGIN")
    private = serialization.load_pem_private_key(
        text[pem_start:], password=_password(password, prompt=f"Password for {path.name}: ", path=path))
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 key")
    return Signer(actor or path.stem, role or "analyst", private)


def load_public(path: Path) -> PublicKey:
    return PublicKey.from_json(json.loads(path.read_text(encoding="utf-8")))


def verify(public_raw: bytes, signature: bytes, data: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, data)
        return True
    except InvalidSignature:
        return False
