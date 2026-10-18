"""Canonical JSON: the exact bytes that get signed and hashed.

Python's ``repr`` and default ``json.dumps`` are not stable enough to sign
(key order, whitespace, float formatting). Canonical form here is a strict
subset of RFC 8785 (JCS): objects with string keys sorted by code point,
no insignificant whitespace, UTF-8, and only strings, integers, booleans,
null, lists and objects. Floats are rejected rather than normalised, so two
implementations can never disagree about ``0.1``.
"""

from __future__ import annotations

import json
from typing import Any


class CanonicalError(ValueError):
    pass


def _check(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise CanonicalError(f"{path}: integer outside the interoperable range")
        return
    if isinstance(value, float):
        raise CanonicalError(f"{path}: floats are not allowed in signed data")
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"{path}: object keys must be strings")
            _check(item, f"{path}.{key}")
        return
    raise CanonicalError(f"{path}: {type(value).__name__} is not canonical JSON")


def dumps(value: Any) -> bytes:
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def loads(data: bytes) -> Any:
    value = json.loads(data.decode("utf-8"))
    if dumps(value) != data:
        raise CanonicalError("bytes are not in canonical form")
    return value
