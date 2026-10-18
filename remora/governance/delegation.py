# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Delegated execution: who besides the proposer may execute a proposal.

The review path and the ACCEPT token bind the proposing principal, so by
default only the proposer executes what it proposed (#935). Some deployments
run a separate service identity that executes on an agent's behalf. This module
decides whether a proposal may name such a delegate.

The rule is two-sided and both sides are explicit:

- the deployment declares, per tenant, which service identities may execute
  for which agents, under ``tenant_access.<tenant>.delegated_executors`` in the
  risk-profile config (``{service_identity: [agent, ...]}``);
- the proposal names the delegate (``delegated_executor``). Nothing is
  delegated ambiently: a declared service that no proposal names executes
  nothing.

A delegation is checked once, at assess time. What was admitted is recorded in
the ``assessed`` record and bound into the ``AuthorizationContext`` hash, which
is what the reviewer approves and what execution compares against. Only the
tenant-specific declaration counts: ``access_defaults`` does not apply, so one
default cannot grant delegation in every tenant, and a service declared only
under another tenant is refused as ``delegate_cross_tenant``.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: Wire reasons, returned as the 409 detail on /v1/execution/assess.
DELEGATE_NOT_DECLARED = "delegate_not_declared"
DELEGATE_CROSS_TENANT = "delegate_cross_tenant"
DELEGATE_IS_PROPOSER = "delegate_is_proposer"


def _declared(tenant_access: Mapping[str, Any], tenant: str) -> Mapping[str, Any]:
    tenant_cfg = tenant_access.get(tenant) if isinstance(tenant_access, Mapping) else None
    declared = tenant_cfg.get("delegated_executors") if isinstance(tenant_cfg, Mapping) else None
    return declared if isinstance(declared, Mapping) else {}


def _agents(declared: Mapping[str, Any], delegate: str) -> set[str]:
    agents = declared.get(delegate)
    if not isinstance(agents, (list, tuple)):
        return set()
    return {a for a in agents if isinstance(a, str) and a}


def delegation_refusal(
    tenant_access: Mapping[str, Any],
    *,
    tenant: str,
    proposer: str,
    delegate: str,
) -> str | None:
    """Why ``proposer`` in ``tenant`` may not name ``delegate``, or None.

    Fails closed on anything it cannot read: no declaration, a malformed one,
    or an agent list that does not name the proposer exactly.
    """
    if not delegate or not proposer:
        return DELEGATE_NOT_DECLARED
    if delegate == proposer:
        return DELEGATE_IS_PROPOSER
    if proposer in _agents(_declared(tenant_access, tenant), delegate):
        return None
    if isinstance(tenant_access, Mapping) and any(
        other != tenant and _agents(_declared(tenant_access, other), delegate)
        for other in tenant_access
    ):
        return DELEGATE_CROSS_TENANT
    return DELEGATE_NOT_DECLARED


def delegated_executor_of(tool_call: Any) -> str:
    """The delegate a proposal names, or "" when it names none.

    Read by attribute so a call rebuilt from the outbox is handled like the
    wire model.
    """
    return str(getattr(tool_call, "delegated_executor", None) or "")
