# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The request a tool call arrived in, as a reference another party can check.

A tool call hash says what was asked. It does not say which request asked it:
two MCP requests with the same tool and arguments hash alike, so an outside
capture of one request can be joined to a REMORA record only by matching
content, and matching content does not show that both describe one execution.

``RequestRef`` is the explicit reference. The front end that received the
request (the MCP gateway) records the transport, the JSON-RPC ``id`` in a
canonical form, and the SHA-256 of the request body bytes as received, before
any parsing. Anyone holding a capture of the same request recomputes the last
two without REMORA code.

The id is canonical, not the bytes on the wire. An id gets a reference only
when it is a string without lone surrogates or an integer within
+/-(2^53 - 1), and its text is what ECMAScript ``JSON.stringify`` writes for
the parsed value, which for these ids equals Python
``json.dumps(value, ensure_ascii=False)``. ``"\\u0037"`` on the wire is
recorded as ``"7"``, while ``7`` and ``"7"`` stay distinct. Only the body
digest covers the exact bytes.

At ACCEPT its digest is bound into the ``AuthorizationContext`` and so into
the signed grant, and redemption recomputes it from the re-presented call. A
grant issued for one request is therefore refused for another before it is
consumed. The reference records what the front end saw. It does not show that
the front end is the only path to the tool, and it says nothing about a
request that never reached REMORA.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

#: The transports a reference may name. A new transport is a new value here,
#: never a free-form string, so a verifier knows what ``body_sha256`` covers.
TRANSPORTS = frozenset({"mcp-streamable-http"})

FORMAT = "remora-request-ref-v1"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_ID_TEXT = 200


@dataclass(frozen=True)
class RequestRef:
    """One received request: transport, JSON-RPC id text, body digest.

    ``jsonrpc_id`` is the id's canonical JSON text (:func:`canonical_jsonrpc_id`).
    ``body_sha256`` is lowercase hex over the HTTP body bytes as received; for
    a batch it covers the whole batch, and ``jsonrpc_id`` names the member.
    """

    transport: str
    jsonrpc_id: str
    body_sha256: str

    def __post_init__(self) -> None:
        if self.transport not in TRANSPORTS:
            raise ValueError(f"request_ref transport must be one of {sorted(TRANSPORTS)}")
        if not isinstance(self.jsonrpc_id, str) or not self.jsonrpc_id:
            raise ValueError("request_ref jsonrpc_id must be the id's JSON text")
        if len(self.jsonrpc_id) > _MAX_ID_TEXT:
            raise ValueError("request_ref jsonrpc_id is too long")
        if canonical_jsonrpc_id(self.jsonrpc_id) != self.jsonrpc_id:
            raise ValueError("request_ref jsonrpc_id is not in canonical form")
        if not isinstance(self.body_sha256, str) or not _HEX64.match(self.body_sha256):
            raise ValueError("request_ref body_sha256 must be 64 lowercase hex characters")

    def to_dict(self) -> dict[str, str]:
        return {
            "transport": self.transport,
            "jsonrpc_id": self.jsonrpc_id,
            "body_sha256": self.body_sha256,
        }

    def canonical_bytes(self) -> bytes:
        """The digest preimage: sorted keys, no whitespace, ASCII only."""
        return json.dumps(
            {"format": FORMAT, **self.to_dict()}, sort_keys=True, separators=(",", ":")
        ).encode("ascii")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestRef:
        unknown = set(data) - {"transport", "jsonrpc_id", "body_sha256"}
        if unknown:
            raise ValueError(f"request_ref has unknown fields: {sorted(unknown)}")
        return cls(
            transport=data.get("transport", ""),
            jsonrpc_id=data.get("jsonrpc_id", ""),
            body_sha256=data.get("body_sha256", ""),
        )


_MAX_SAFE_INTEGER = 2**53 - 1


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def canonical_jsonrpc_id(text: str) -> str:
    """The canonical text of a JSON-RPC id given as JSON text. Raises ValueError.

    Accepted: a string without lone surrogates, or an integer within
    +/-(2^53 - 1). JSON-RPC also allows a fractional id, but the gateway
    cannot carry one unchanged, so it gets no reference; null marks a
    notification, never a request REMORA executes.
    """
    try:
        value = json.loads(text, parse_constant=_refuse_constant)
    except json.JSONDecodeError as exc:
        raise ValueError("request_ref jsonrpc_id is not JSON text") from exc
    if isinstance(value, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ValueError("request_ref jsonrpc_id contains a lone surrogate")
    elif type(value) is int:
        if abs(value) > _MAX_SAFE_INTEGER:
            raise ValueError("request_ref jsonrpc_id is beyond +/-(2^53 - 1)")
    else:
        raise ValueError("request_ref jsonrpc_id must be a string or a safe integer")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def request_ref_of(tool_call: Any) -> RequestRef | None:
    """The reference a call carries, or None. Raises ValueError when malformed.

    Read by attribute, like the task identity, so the wire model and a call
    rebuilt from the outbox are handled alike.
    """
    raw = getattr(tool_call, "request_ref", None)
    if raw is None:
        return None
    if isinstance(raw, RequestRef):
        return raw
    data = raw.model_dump() if hasattr(raw, "model_dump") else raw
    if not isinstance(data, dict):
        raise ValueError("request_ref must be an object")
    return RequestRef.from_dict(data)


__all__ = ["FORMAT", "TRANSPORTS", "RequestRef", "canonical_jsonrpc_id", "request_ref_of"]
