# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Strict JSON, RFC 8785 (JCS) canonicalization and Ed25519 for the Horizon #55 row.

A standalone consumer: it imports no REMORA package and none of the
producer's code. Its JCS covers the subset the MUSUBI companion profile
allows (COMPANION_v0.md section 3): objects, arrays, strings, integers
within plus or minus 2^53 - 1, true, false and null. Floats are refused at
parse time, so the number serialisation rules of RFC 8785 that need
ECMAScript formatting never apply.

Parsing is strict: duplicate object names, NaN, Infinity, floats, integers
out of range and nesting deeper than ``MAX_DEPTH`` are rejected with
``StrictJSONError``, never coerced.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_INT = 2**53 - 1
MAX_DEPTH = 64
MAX_BYTES = 4 * 1024 * 1024


class StrictJSONError(ValueError):
    """Input that the strict reader refuses. ``code`` is machine-readable."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise StrictJSONError("duplicate_key", key)
        out[key] = value
    return out


def _constant(name: str) -> Any:
    raise StrictJSONError("non_finite_number", name)


def _float(text: str) -> Any:
    raise StrictJSONError("float_not_allowed", text)


def _int(text: str) -> int:
    value = int(text)
    if abs(value) > MAX_INT:
        raise StrictJSONError("integer_out_of_range", text)
    return value


def _depth(value: Any, level: int = 0) -> None:
    if level > MAX_DEPTH:
        raise StrictJSONError("nesting_too_deep", str(level))
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, level + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, level + 1)


def loads(data: bytes) -> Any:
    """Parse UTF-8 JSON bytes strictly."""
    if len(data) > MAX_BYTES:
        raise StrictJSONError("input_too_large", str(len(data)))
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJSONError("not_utf8", str(exc)) from None
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant,
                           parse_float=_float, parse_int=_int)
    except StrictJSONError:
        raise
    except (ValueError, RecursionError) as exc:
        raise StrictJSONError("invalid_json", str(exc)[:200]) from None
    _depth(value)
    return value


_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r",
            "\t": "\\t"}


def _string(text: str) -> str:
    parts = ['"']
    for ch in text:
        if ch in _ESCAPES:
            parts.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            parts.append(f"\\u{ord(ch):04x}")
        elif 0xD800 <= ord(ch) <= 0xDFFF:
            raise StrictJSONError("lone_surrogate", hex(ord(ch)))
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def _jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise StrictJSONError("integer_out_of_range", str(value))
        return str(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 section 3.2.3: names sorted by their UTF-16 code units.
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + _jcs(value[k]) for k in keys) + "}"
    raise StrictJSONError("unsupported_type", type(value).__name__)


def jcs(value: Any) -> bytes:
    """The RFC 8785 canonical UTF-8 bytes of *value*."""
    return _jcs(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def without(obj: dict[str, Any], *names: str) -> dict[str, Any]:
    return {k: v for k, v in obj.items() if k not in names}


def ed25519_verify(public_hex: str, signature_hex: str, message: bytes) -> bool:
    """True when *signature_hex* is a valid Ed25519 signature by *public_hex*.

    A malformed key or signature is a failed verification, never an
    exception: the inputs are untrusted data.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not (isinstance(public_hex, str) and isinstance(signature_hex, str)
            and len(public_hex) == 64 and len(signature_hex) == 128):
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        key.verify(bytes.fromhex(signature_hex), message)
    except (ValueError, InvalidSignature):
        return False
    return True
