# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The recipient set a flow check approved, carried to the mediated effects (IFC-12).

Under flow control the authority computes, for one call, the set ``R`` of
recipients its payload may reach (:func:`remora.flow.check.recipients`): the
hosts of its URL arguments, the addresses of its e-mail arguments, the
provider. The flow check refuses the call when the payload's label does not
flow to every member of ``R``. The tool's code may still send the payload
somewhere else, which is what §3.5.1 of the derived information-flow control
design closes: a network effect is admitted only on a resource whose
recipient is in ``R``.

Two functions make that checkable without the flow package: the canonical
digest of ``R`` that the lease signs (``flow_recipients_digest``), and the
recipient a mediated effect's canonical resource names. Network capabilities
(``network.*``) name the host of an http(s) resource as ``ext://<host>``, the
form the flow check gives a URL argument. A resource that already is a
recipient (``ext://``, ``email://``, ``iban://``) names itself. Every other
capability names no recipient and is not narrowed here: a write to a
``workspace://`` or ``database://`` resource reaches whoever may read it,
which the flow check judges through the resource ACL, not through ``R``.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from remora.capabilities.resource import ResourceRefused, canonical_resource

__all__ = ["effect_recipient", "recipients_digest"]

_DIGEST_DOMAIN = b"REMORA/FLOW-RECIPIENTS/v1\x00"
_RECIPIENT_SCHEMES = frozenset({"ext", "email", "iban"})
_HOST_SCHEMES = frozenset({"http", "https"})


def recipients_digest(recipients: Iterable[str]) -> str:
    """The canonical digest of a recipient set: sorted, de-duplicated, JSON."""
    body = json.dumps(sorted(set(recipients)), separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(_DIGEST_DOMAIN + body.encode("utf-8")).hexdigest()


def effect_recipient(capability: str, resource: str) -> str | None:
    """The recipient a mediated effect on ``resource`` names, or None.

    ``resource`` is a canonical resource. A ``network.*`` capability on an
    http(s) resource names ``ext://<host>`` (the port is not part of the
    recipient, as it is not for a URL argument). A resource whose scheme is a
    recipient scheme names itself. Anything else names no recipient. An
    ambiguous resource names no recipient either, and the mediator has already
    refused it.
    """
    try:
        canonical = canonical_resource(resource)
    except ResourceRefused:
        return None
    scheme, _, rest = canonical.partition("://")
    if scheme in _RECIPIENT_SCHEMES:
        return canonical
    if capability.startswith("network.") and scheme in _HOST_SCHEMES:
        authority = rest.partition("/")[0]
        host = authority.rsplit(":", 1)[0] if ":" in authority else authority
        return f"ext://{host}" if host else None
    return None
