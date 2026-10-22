# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Cumulative spend budgets on governed tool calls.

A deployment declares which tools spend (the argument that carries the
amount and the one that carries the unit) and a budget per tenant, principal
and unit. Before a budgeted call is dispatched, its amount is reserved
against the budget in a durable ledger; a call that would take the running
total past the limit is refused and never reaches the tool.

The budget is keyed by the authenticated principal the lease names, never by
anything the caller chooses: a task or context identifier is the caller's to
pick, and a budget keyed by it could be reset by naming a new one.

What this guarantees: on one host, the sum of reserved amounts never exceeds
the limit (``SpendLedger``: one SQLite transaction, ``CHECK(spent<=cap)``).
A reservation is never returned, so a call that was reserved and then failed
or never ran still counts; the budget errs towards refusing. It is not a
distributed budget across hosts, and it does not observe what the tool or
the payment rail actually did.
"""
from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "remora-spend-budget/v1"
MAX_LIMIT = 1_000_000  # the ledger's bound on a cap and on one reservation

#: Refusal reasons, as they appear in dispatch results and audit records.
AMOUNT_INVALID = "spend_amount_invalid"
UNIT_INVALID = "spend_unit_invalid"
PRINCIPAL_MISSING = "spend_principal_missing"
UNDECLARED = "spend_budget_undeclared"
BUDGET_EXHAUSTED = "spend_budget_exhausted"
BUDGET_CLOSED = "spend_budget_closed"
BUDGET_CHANGED = "spend_budget_changed"
LEDGER_UNAVAILABLE = "spend_ledger_unavailable"


RESERVED, DUPLICATE, EXHAUSTED, CLOSED = "reserved", "duplicate", "exhausted", "closed"


class SpendLedger:
    """Single-host SQLite ledger of reserved spend per budget.

    One transaction per reservation (``BEGIN IMMEDIATE``), a conditional
    update and ``CHECK(spent <= cap)``: the sum of reservations never passes
    the cap. A reservation is never returned. ``(budget_key, operation_id)``
    is unique, so a retry of one operation is reported as ``duplicate`` and
    charged once; the same key with another amount is refused.

    Kept apart from the WS1 task ledger on purpose: the enforcement core does
    not import the verification library (tests/verification/
    test_architecture_boundary.py).
    """

    def __init__(self, path: str | Path) -> None:
        from remora.persistence.sqlite_path import refuse_memory_db

        self.path = str(path)
        refuse_memory_db(self.path, what="spend budget ledger")
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS spend_budget (
                    budget_key TEXT PRIMARY KEY, binding TEXT NOT NULL,
                    cap INTEGER NOT NULL CHECK(cap >= 0),
                    spent INTEGER NOT NULL DEFAULT 0 CHECK(spent >= 0),
                    closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0,1)),
                    CHECK(spent <= cap)
                );
                CREATE TABLE IF NOT EXISTS spend_reservation (
                    budget_key TEXT NOT NULL REFERENCES spend_budget(budget_key),
                    operation_id TEXT NOT NULL, request_hash TEXT NOT NULL,
                    amount INTEGER NOT NULL CHECK(amount > 0),
                    PRIMARY KEY(budget_key, operation_id)
                );
            """)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5.0)
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _bounded(*values: str) -> None:
        for value in values:
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError("invalid bounded identifier")

    def _ensure(self, conn: sqlite3.Connection, key: str, binding: str, cap: int) -> None:
        row = conn.execute("SELECT binding FROM spend_budget WHERE budget_key=?",
                           (key,)).fetchone()
        if row is None:
            if type(cap) is not int or not 0 <= cap <= MAX_LIMIT:
                raise ValueError("invalid cap")
            conn.execute("INSERT INTO spend_budget(budget_key,binding,cap) VALUES(?,?,?)",
                         (key, binding, cap))
        elif row[0] != binding:
            raise ValueError("budget binding mismatch")

    def remaining(self, key: str, binding: str, cap: int) -> int:
        self._bounded(key, binding)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._ensure(conn, key, binding, cap)
            spent, closed, limit = conn.execute(
                "SELECT spent,closed,cap FROM spend_budget WHERE budget_key=?",
                (key,)).fetchone()
        return 0 if closed else limit - spent

    def reserve(self, key: str, binding: str, cap: int, operation_id: str,
                request_hash: str, amount: int) -> str:
        self._bounded(key, binding, operation_id, request_hash)
        if type(amount) is not int or not 1 <= amount <= MAX_LIMIT:
            raise ValueError("invalid amount")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._ensure(conn, key, binding, cap)
            prior = conn.execute(
                "SELECT request_hash,amount FROM spend_reservation "
                "WHERE budget_key=? AND operation_id=?", (key, operation_id)).fetchone()
            if prior is not None:
                if prior != (request_hash, amount):
                    raise ValueError("operation reused for a different request")
                return DUPLICATE
            changed = conn.execute(
                "UPDATE spend_budget SET spent=spent+? "
                "WHERE budget_key=? AND closed=0 AND spent+?<=cap",
                (amount, key, amount)).rowcount
            if changed != 1:
                closed = conn.execute("SELECT closed FROM spend_budget WHERE budget_key=?",
                                      (key,)).fetchone()[0]
                return CLOSED if closed else EXHAUSTED
            conn.execute("INSERT INTO spend_reservation VALUES(?,?,?,?)",
                         (key, operation_id, request_hash, amount))
            return RESERVED

    def close(self, key: str, binding: str) -> None:
        """Stop a budget: every later reservation is refused as closed."""
        self._bounded(key, binding)
        with self._connect() as conn:
            if conn.execute("UPDATE spend_budget SET closed=1 WHERE budget_key=? AND binding=?",
                            (key, binding)).rowcount != 1:
                raise ValueError("unknown budget or binding mismatch")


class SpendPolicyError(ValueError):
    """The declared spend policy is malformed; the deployment must not start."""


@dataclass(frozen=True)
class SpendTool:
    amount_argument: str
    unit_argument: str


@dataclass(frozen=True)
class SpendBudget:
    budget_id: str
    tenant: str
    principal: str
    unit: str
    limit: int

    @property
    def ledger_key(self) -> str:
        return f"spend/{self.budget_id}"

    @property
    def binding(self) -> str:
        """Binds the ledger row to every declared term, the limit included.

        A row created under one declaration refuses another one with the same
        id, so a limit cannot be raised in place; a new budget needs a new id.
        """
        terms = "\x1f".join((SCHEMA, self.budget_id, self.tenant, self.principal,
                             self.unit, str(self.limit)))
        return hashlib.sha256(terms.encode("utf-8")).hexdigest()


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise SpendPolicyError(f"{what} must be a non-empty string of at most 200 characters")
    return value


@dataclass(frozen=True)
class SpendPolicy:
    tools: Mapping[str, SpendTool]
    budgets: tuple[SpendBudget, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SpendPolicy":
        if not isinstance(data, Mapping) or data.get("schema") != SCHEMA:
            raise SpendPolicyError(f"spend policy schema must be {SCHEMA!r}")
        raw_tools = data.get("tools")
        if not isinstance(raw_tools, Mapping) or not raw_tools:
            raise SpendPolicyError("a spend policy names at least one spending tool")
        tools = {}
        for name, spec in raw_tools.items():
            if not isinstance(spec, Mapping):
                raise SpendPolicyError(f"tool {name!r}: expected an object")
            amount = _text(spec.get("amount_argument"), f"tool {name!r} amount_argument")
            unit = _text(spec.get("unit_argument"), f"tool {name!r} unit_argument")
            if amount == unit:
                raise SpendPolicyError(f"tool {name!r}: amount and unit are one argument")
            tools[_text(name, "tool name")] = SpendTool(amount, unit)
        budgets = []
        for raw in data.get("budgets") or ():
            if not isinstance(raw, Mapping):
                raise SpendPolicyError("each budget is an object")
            limit = raw.get("limit")
            if type(limit) is not int or not 0 <= limit <= MAX_LIMIT:
                raise SpendPolicyError(f"budget limit must be an integer in [0, {MAX_LIMIT}]")
            budgets.append(SpendBudget(
                budget_id=_text(raw.get("budget_id"), "budget_id"),
                tenant=_text(raw.get("tenant"), "tenant"),
                principal=_text(raw.get("principal"), "principal"),
                unit=_text(raw.get("unit"), "unit"), limit=limit))
        ids = [b.budget_id for b in budgets]
        if len(set(ids)) != len(ids):
            raise SpendPolicyError("budget_id values must be unique")
        scopes = [(b.tenant, b.principal, b.unit) for b in budgets]
        if len(set(scopes)) != len(scopes):
            raise SpendPolicyError("two budgets cover the same tenant, principal and unit")
        return cls(tools=dict(tools), budgets=tuple(budgets))

    def budget_for(self, tenant: str, principal: str, unit: str) -> SpendBudget | None:
        return next((b for b in self.budgets
                     if (b.tenant, b.principal, b.unit) == (tenant, principal, unit)), None)


@dataclass(frozen=True)
class SpendCharge:
    """What one call would spend, or why it cannot be charged."""

    budget: SpendBudget | None
    amount: int
    refusal: str | None


class SpendGuard:
    """Reserves a call's amount against its budget before dispatch."""

    def __init__(self, policy: SpendPolicy, ledger: SpendLedger) -> None:
        self.policy = policy
        self.ledger = ledger

    def governs(self, tool_name: str) -> bool:
        return tool_name in self.policy.tools

    def charge_for(self, *, tenant: str, principal: str, tool_name: str,
                   arguments: Any) -> SpendCharge:
        tool = self.policy.tools[tool_name]
        args = arguments if isinstance(arguments, Mapping) else {}
        amount = args.get(tool.amount_argument)
        if type(amount) is not int or not 1 <= amount <= MAX_LIMIT:
            return SpendCharge(None, 0, AMOUNT_INVALID)
        unit = args.get(tool.unit_argument)
        if not isinstance(unit, str) or not unit:
            return SpendCharge(None, amount, UNIT_INVALID)
        if not principal:
            return SpendCharge(None, amount, PRINCIPAL_MISSING)
        budget = self.policy.budget_for(tenant, principal, unit)
        if budget is None:
            return SpendCharge(None, amount, UNDECLARED)
        return SpendCharge(budget, amount, None)

    def remaining(self, budget: SpendBudget) -> int:
        """Unreserved amount; raises ``ValueError`` when the row is another budget's."""
        return self.ledger.remaining(budget.ledger_key, budget.binding, budget.limit)

    def preview(self, *, tenant: str, principal: str, tool_name: str,
                arguments: Any) -> str | None:
        """Refusal reason if this call could not be reserved now; reserves nothing.

        Advisory: the reservation at dispatch decides. A call that passes here
        can still be refused there when other calls spent the budget meanwhile.
        """
        charge = self.charge_for(tenant=tenant, principal=principal, tool_name=tool_name,
                                 arguments=arguments)
        if charge.refusal is not None or charge.budget is None:
            return charge.refusal
        try:
            left = self.remaining(charge.budget)
        except ValueError:
            return BUDGET_CHANGED
        except Exception:
            return LEDGER_UNAVAILABLE
        return None if charge.amount <= left else BUDGET_EXHAUSTED

    def reserve(self, *, tenant: str, principal: str, tool_name: str, arguments: Any,
                operation_id: str, request_hash: str) -> str | None:
        """Reserve the call's amount; None when it may run, else the refusal reason.

        ``operation_id`` names the lease the call runs under, so a retry of
        one lease (a crash between this reservation and the nonce consumption)
        finds its own reservation and is not charged twice.
        """
        charge = self.charge_for(tenant=tenant, principal=principal, tool_name=tool_name,
                                 arguments=arguments)
        if charge.refusal is not None or charge.budget is None:
            return charge.refusal
        budget = charge.budget
        try:
            status = self.ledger.reserve(budget.ledger_key, budget.binding, budget.limit,
                                         operation_id, request_hash, charge.amount)
        except ValueError:
            return BUDGET_CHANGED
        except Exception:
            return LEDGER_UNAVAILABLE
        if status in (RESERVED, DUPLICATE):
            return None
        return {EXHAUSTED: BUDGET_EXHAUSTED, CLOSED: BUDGET_CLOSED}.get(status,
                                                                      LEDGER_UNAVAILABLE)
