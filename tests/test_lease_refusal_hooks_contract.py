# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Lease verification and dispatcher refusal hooks as a tested contract.

The 2026-10-13 mutation sweep over ``remora/enforcement/lease.py`` left
survivors outside ``GovernedToolDispatcher.dispatch`` that no suite pinned:
the exact verdicts of ``ExecutionLease.verify_authenticity``, ``verify`` and
``verify_historical``, the boundary of the TTL cap in ``issue``, the clock
parser, the identity an unknown-state error carries, the records the
independent recorder receives, and the governance events each refusal hook
emits. This file pins them.

Two conventions follow ``tests/test_governance_event_contract.py``. Events are
captured with caplog on the ``remora.governance`` logger and asserted on the
structured payload (``record.remora``), never on rendered text. Verdicts are
compared as whole ``LeaseVerificationResult`` values, so a refusal that reports
``verified=None`` instead of ``False`` is a failure, not a pass on truthiness.

The hooks are called directly. ``tests/test_dispatch_refusal_contract.py``
covers how ``dispatch`` orders and combines them; this file covers what each
one decides and records on its own. Mutants argued equivalent are listed in
``tests/data/mutation_equivalent_lease.txt``.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from remora.audit.recorder import RecorderReceipt, RecorderUnavailable
from remora.enforcement import lease_signing as signing
from remora.enforcement.binding_policy import BINDINGS, BindingPolicy
from remora.enforcement.lease import (
    MAX_LEASE_TTL_SECONDS,
    ExecutionLease,
    GovernedToolDispatcher,
    LeaseRefused,
    LeaseVerificationResult,
    ToolExecutionStateUnknown,
    _parse_utc,
)
from remora.governance.plan_binding import PlanBinding
from remora.governance.procedure import ProcedureContract, StepPattern, absence
from remora.governance.task_identity import TaskIdentity

LOGGER = "remora.governance"
ISSUED_AT = "2026-07-20T12:00:00+00:00"
DURING = "2026-07-20T12:01:00+00:00"
EXPIRES = "2026-07-20T12:02:00+00:00"
TENANT = "acme"
ACTOR = "agent-1"
TOOL = "wo_close"
ARGS = {"id": "WO-1"}
TARGET = "staging"
BUNDLE = "bundle-hooks-1"
SEED = "11" * 32
TASK_A = TaskIdentity(context_id="ctx-1", task_id="task-a")
TASK_B = TaskIdentity(context_id="ctx-1", task_id="task-b")

_KEY_ENV = (
    "REMORA_LEASE_SIGNING_KEY",
    "REMORA_PDP_SIGNING_KEY",
    "REMORA_LEASE_SIGNING_KEY_ED25519_PRIVATE",
    "REMORA_LEASE_VERIFY_KEY_ED25519_PUBLIC",
    "REMORA_LEASE_ACCEPT_HMAC",
    "REMORA_LEASE_SIGNING_KID",
    "REMORA_LEASE_REVOKED_KIDS",
    "REMORA_SIGNATURE_FORMAT",
    "REMORA_RUNTIME_PROFILE",
    "REMORA_EXECUTION_DOMAIN_ROLE",
)


@pytest.fixture(autouse=True)
def _hmac_research(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Research posture with one HMAC lease key and nothing else configured."""
    for name in _KEY_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REMORA_LEASE_SIGNING_KEY", "refusal-hook-key")
    return monkeypatch


def _issue(**overrides: Any) -> ExecutionLease:
    params: dict[str, Any] = dict(
        decision="accept", tenant_id=TENANT, actor_identity=ACTOR, tool_name=TOOL,
        arguments=ARGS, target_environment=TARGET, policy_bundle_hash=BUNDLE,
        issued_at=ISSUED_AT, expires_at=EXPIRES, proposal_id="prop-1",
        grant_jti="jti-1",
    )
    params.update(overrides)
    return ExecutionLease.issue(**params)


def _resigned(lease: ExecutionLease, **changes: Any) -> ExecutionLease:
    """A lease with ``changes`` applied and a valid signature over them."""
    changed = ExecutionLease.from_dict({**lease.to_dict(), **changes})
    signature = signing.sign_payload(
        ExecutionLease._canonical_payload(changed._signed_fields()), alg=changed.sig_alg)
    return dataclasses.replace(changed, signature=signature)


def _verify(lease: ExecutionLease, **overrides: Any) -> LeaseVerificationResult:
    kwargs: dict[str, Any] = dict(tool_name=TOOL, arguments=ARGS, tenant_id=TENANT,
                                  target_environment=TARGET, now=DURING,
                                  actor_identity=ACTOR)
    kwargs.update(overrides)
    return lease.verify(**kwargs)


def _events(caplog: pytest.LogCaptureFixture, name: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records
            if r.name == LOGGER and r.getMessage().startswith(name + " ")]


def _only_event(caplog: pytest.LogCaptureFixture, name: str) -> logging.LogRecord:
    records = _events(caplog, name)
    assert len(records) == 1, [r.getMessage() for r in caplog.records]
    return records[0]


def _payload(record: logging.LogRecord) -> dict[str, Any]:
    return record.remora  # type: ignore[attr-defined, no-any-return]


def _ed25519_public(seed: str = SEED) -> str:
    from remora.crypto import SignatureDomain, SigningKey

    key = SigningKey.from_text(seed, [SignatureDomain.EXECUTION_LEASE]).verification_key()
    return key.public_bytes.hex()


def _all_bindings(state: str = "UNVERIFIABLE", **overrides: str) -> dict[str, str]:
    return {**{name: state for name in BINDINGS}, **overrides}


# -- ToolExecutionStateUnknown ---------------------------------------------------------


def test_an_unknown_state_error_invents_no_identity_and_keeps_its_message() -> None:
    """The operator acts on these fields. A default that is not empty would
    name a proposal, tenant or execution that never existed."""
    exc = ToolExecutionStateUnknown("tool raised after the nonce was consumed")
    assert str(exc) == "tool raised after the nonce was consumed"
    assert (exc.proposal_id, exc.tenant_id, exc.tool_name) == ("", "", "")
    assert exc.nested_effects == {"mediated": False, "count": 0, "settled": True}
    assert exc.effect_graph is None
    assert exc.execution_context_hash == ""
    assert exc.execution_id == ""
    assert exc.dispatch_check is None


# -- _parse_utc ------------------------------------------------------------------------


def test_the_clock_parser_reads_z_as_utc() -> None:
    """Issuers emit ``Z``; it must mean UTC, not fail the expiry check."""
    assert _parse_utc("2026-07-20T12:00:00Z") == datetime(2026, 7, 20, 12, tzinfo=UTC)


def test_the_clock_parser_treats_a_naive_timestamp_as_utc() -> None:
    """A naive timestamp compared with an aware one would raise TypeError."""
    parsed = _parse_utc("2026-07-20T12:00:00")
    assert parsed.tzinfo is UTC
    assert parsed == datetime(2026, 7, 20, 12, tzinfo=UTC)


def test_the_clock_parser_keeps_an_explicit_offset() -> None:
    parsed = _parse_utc("2026-07-20T14:00:00+02:00")
    assert parsed.utcoffset() == timedelta(hours=2)
    assert parsed == datetime(2026, 7, 20, 12, tzinfo=UTC)


def test_the_clock_parser_accepts_only_the_upper_case_z_suffix() -> None:
    """One spelling of UTC for signed timestamps. Accepting more is a decision
    to take on purpose, not something a parser change does quietly."""
    with pytest.raises(ValueError):
        _parse_utc("2026-07-20T12:00:00z")


# -- ExecutionLease.issue -------------------------------------------------------------


def test_an_unbound_issue_carries_empty_bindings_not_placeholders() -> None:
    """Every optional binding defaults to absent. A non-empty default would be
    signed into the lease and look like a binding someone declared."""
    lease = ExecutionLease.issue(
        decision="accept", tenant_id=TENANT, actor_identity=ACTOR, tool_name=TOOL,
        arguments=ARGS, target_environment=TARGET, policy_bundle_hash=BUNDLE,
        issued_at=ISSUED_AT)
    assert lease.tool_contract_bundle_hash == ""
    assert lease.intent_authority_hash == ""
    assert lease.toolspec_hash == ""
    assert lease.toolspec_version == 0
    assert lease.grant_jti == ""
    assert lease.proposal_id == ""


def test_a_non_accept_decision_is_refused_naming_the_decision() -> None:
    with pytest.raises(LeaseRefused,
                       match=r"^execution lease refused: decision 'verify' is not 'accept'$"):
        _issue(decision="verify")


def test_the_ttl_cap_is_inclusive() -> None:
    """``(0, MAX]``: exactly the cap is allowed, one second more is not."""
    issued = _parse_utc(ISSUED_AT)
    at_cap = (issued + timedelta(seconds=MAX_LEASE_TTL_SECONDS)).isoformat()
    over_cap = (issued + timedelta(seconds=MAX_LEASE_TTL_SECONDS + 1)).isoformat()
    assert _issue(expires_at=at_cap).expires_at == at_cap
    with pytest.raises(ValueError, match="lease TTL must be in"):
        _issue(expires_at=over_cap)
    with pytest.raises(ValueError, match="lease TTL must be in"):
        _issue(expires_at=ISSUED_AT)


def test_the_ttl_floor_is_exclusive_at_zero_not_at_one() -> None:
    """A one-second lease is short, not empty: it issues."""
    one_second = (_parse_utc(ISSUED_AT) + timedelta(seconds=1)).isoformat()
    assert _issue(expires_at=one_second).expires_at == one_second


# -- ExecutionLease.digest ------------------------------------------------------------


def test_the_digest_is_the_signed_fields_then_the_signature() -> None:
    """The digest is the parent identity a nested execution and its graph
    record, so its preimage is a format: canonical signed fields, '.', the
    signature. Pinned against an independent recomputation."""
    lease = _issue()
    expected = hashlib.sha256(
        json.dumps(lease._signed_fields(), sort_keys=True, separators=(",", ":")).encode()
        + b"." + lease.signature.encode()).hexdigest()
    assert lease.digest() == expected


def test_the_digest_changes_with_a_signed_field_under_the_same_signature() -> None:
    """Two leases carrying one signature are still two leases if a signed
    field differs; the digest must not collapse them."""
    lease = _issue()
    other = dataclasses.replace(lease, target_environment="prod")
    assert other.signature == lease.signature
    assert other.digest() != lease.digest()


def test_without_any_key_the_lease_is_unsigned_with_the_default_scheme(
        _hmac_research: pytest.MonkeyPatch) -> None:
    """The unsigned form is a fixed shape: empty signature and kid, HMAC
    named as the scheme. verify() refuses it on that shape."""
    _hmac_research.delenv("REMORA_LEASE_SIGNING_KEY")
    lease = _issue()
    assert lease.is_signed is False
    assert lease.signature == ""
    assert lease.kid == ""
    assert lease.sig_alg == signing.ALG_HMAC
    assert lease.verify_authenticity(now=DURING) == LeaseVerificationResult(
        False, "lease_not_signed")


def test_format_v2_without_an_ed25519_key_refuses_to_issue(
        _hmac_research: pytest.MonkeyPatch) -> None:
    """The refusal names the variable an operator must set."""
    _hmac_research.setenv("REMORA_SIGNATURE_FORMAT", "v2")
    with pytest.raises(
            LeaseRefused,
            match=(r"^lease format v2 requires the Ed25519 lease key "
                   r"\(REMORA_LEASE_SIGNING_KEY_ED25519_PRIVATE\); HMAC and unsigned "
                   r"leases are not issued under it$")):
        _issue()


def test_a_verification_only_process_refuses_to_issue(
        _hmac_research: pytest.MonkeyPatch) -> None:
    """The message says why: the process holds only verification material."""
    _hmac_research.delenv("REMORA_LEASE_SIGNING_KEY")
    _hmac_research.setenv("REMORA_LEASE_VERIFY_KEY_ED25519_PUBLIC", "aa" * 32)
    with pytest.raises(
            LeaseRefused,
            match=(r"^this process holds only lease VERIFICATION material and "
                   r"cannot issue authority; issuing requires the PDP private key$")):
        _issue()


def test_the_issued_event_carries_the_task_binding(caplog: pytest.LogCaptureFixture) -> None:
    """Task-scoped audit joins lease issuance to its task on these fields."""
    caplog.set_level(logging.INFO, logger=LOGGER)
    _issue(task_identity=TASK_A)
    payload = _payload(_only_event(caplog, "lease.issued"))
    assert payload["context_id"] == "ctx-1"
    assert payload["task_id"] == "task-a"


def test_an_unbound_issued_event_carries_no_task_fields(
        caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    _issue()
    payload = _payload(_only_event(caplog, "lease.issued"))
    assert "context_id" not in payload and "task_id" not in payload


# -- ExecutionLease.verify_historical -------------------------------------------------


def test_historical_verification_refuses_a_lease_marked_unsigned() -> None:
    """Either half missing is unsigned, even when the other half is valid."""
    signed = _issue()
    marked_unsigned = dataclasses.replace(signed, is_signed=False)
    without_signature = dataclasses.replace(signed, signature="")
    expected = LeaseVerificationResult(False, "lease_not_signed")
    assert marked_unsigned.verify_historical() == expected
    assert without_signature.verify_historical() == expected


def test_historical_verification_without_a_key_cannot_reach_a_verdict(
        _hmac_research: pytest.MonkeyPatch) -> None:
    lease = _issue()
    _hmac_research.delenv("REMORA_LEASE_SIGNING_KEY")
    assert lease.verify_historical() == LeaseVerificationResult(False, "no_signing_key")


def test_historical_verification_refuses_a_forged_signature() -> None:
    forged = dataclasses.replace(_issue(), signature="00" * 32)
    assert forged.verify_historical() == LeaseVerificationResult(False, "signature_invalid")


def test_historical_verification_names_a_v1_lease() -> None:
    assert _issue().verify_historical() == LeaseVerificationResult(True, "historical_v1")


# -- ExecutionLease.verify_authenticity ----------------------------------------------


def test_an_authentic_lease_reports_authentic() -> None:
    assert _issue().verify_authenticity(now=DURING) == LeaseVerificationResult(
        True, "authentic")


def test_the_validity_window_is_issued_inclusive_and_expiry_exclusive() -> None:
    lease = _issue()
    assert lease.verify_authenticity(now=ISSUED_AT).reason == "authentic"
    assert lease.verify_authenticity(now="2026-07-20T11:59:59.999999+00:00") == (
        LeaseVerificationResult(False, "lease_not_yet_valid"))
    assert lease.verify_authenticity(now=EXPIRES) == LeaseVerificationResult(
        False, "lease_expired")


def test_a_z_suffixed_or_naive_clock_is_read_as_utc() -> None:
    lease = _issue()
    assert lease.verify_authenticity(now="2026-07-20T12:01:00Z").reason == "authentic"
    assert lease.verify_authenticity(now="2026-07-20T12:01:00").reason == "authentic"


def test_an_unparseable_clock_refuses() -> None:
    expected = LeaseVerificationResult(False, "expiry_unparseable")
    assert _issue().verify_authenticity(now="not-a-time") == expected
    assert _issue().verify_authenticity(now="2026-07-20T12:01:00z") == expected


def test_a_correctly_signed_non_accept_decision_is_refused() -> None:
    """The decision is checked after the signature, so a validly signed
    non-accept lease still never authorizes."""
    lease = _resigned(_issue(), decision="verify")
    assert lease.verify_authenticity(now=DURING) == LeaseVerificationResult(
        False, "decision_not_accept")


def _v1_ed25519_lease_under_strict_v2(monkeypatch: pytest.MonkeyPatch) -> ExecutionLease:
    pytest.importorskip("cryptography")
    monkeypatch.delenv("REMORA_LEASE_SIGNING_KEY")
    monkeypatch.setenv("REMORA_LEASE_SIGNING_KEY_ED25519_PRIVATE", SEED)
    monkeypatch.setenv("REMORA_EXECUTION_DOMAIN_ROLE", "authority")
    monkeypatch.setenv("REMORA_RUNTIME_PROFILE", "review/v1")
    lease = _issue(issued_at=datetime.now(UTC).isoformat(), expires_at=None)
    monkeypatch.setenv("REMORA_RUNTIME_PROFILE", "review/v2")
    monkeypatch.delenv("REMORA_LEASE_SIGNING_KEY_ED25519_PRIVATE")
    monkeypatch.setenv("REMORA_LEASE_VERIFY_KEY_ED25519_PUBLIC", _ed25519_public())
    monkeypatch.setenv("REMORA_EXECUTION_DOMAIN_ROLE", "executor")
    return lease


def test_a_legacy_format_refusal_is_reported_as_itself(
        _hmac_research: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    """A v1 lease under strict v2 is a migration fact, not a forgery: the
    event says which scheme was refused and for whom."""
    lease = _v1_ed25519_lease_under_strict_v2(_hmac_research)
    caplog.set_level(logging.INFO, logger=LOGGER)
    assert lease.verify_authenticity() == LeaseVerificationResult(
        False, "lease_format_legacy")
    record = _only_event(caplog, "lease.format_legacy_refused")
    assert record.levelno == logging.WARNING
    payload = _payload(record)
    assert set(payload) == {"sig_alg", "tenant_id", "tool_name", "detail"}
    assert payload["sig_alg"] == signing.ALG_ED25519
    assert payload["tenant_id"] == TENANT
    assert payload["tool_name"] == TOOL
    assert "refused for live authority under a strict v2 contract" in payload["detail"]


def test_a_revoked_key_refusal_names_the_key(
        _hmac_research: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    pytest.importorskip("cryptography")
    _hmac_research.delenv("REMORA_LEASE_SIGNING_KEY")
    _hmac_research.setenv("REMORA_SIGNATURE_FORMAT", "v2")
    _hmac_research.setenv("REMORA_LEASE_SIGNING_KEY_ED25519_PRIVATE", SEED)
    lease = _issue(issued_at=datetime.now(UTC).isoformat(), expires_at=None)
    _hmac_research.setenv("REMORA_LEASE_REVOKED_KIDS", lease.kid)
    caplog.set_level(logging.INFO, logger=LOGGER)
    assert lease.verify_authenticity() == LeaseVerificationResult(False, "lease_key_revoked")
    record = _only_event(caplog, "lease.key_revoked")
    assert record.levelno == logging.WARNING
    payload = _payload(record)
    assert set(payload) == {"kid", "tenant_id", "tool_name", "detail"}
    assert payload["kid"] == lease.kid
    assert payload["tenant_id"] == TENANT
    assert payload["tool_name"] == TOOL
    assert "is revoked (REMORA_LEASE_REVOKED_KIDS)" in payload["detail"]


def test_a_refused_hmac_scheme_is_reported_as_unavailable_not_forged(
        _hmac_research: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    lease = _issue()
    _hmac_research.setenv("REMORA_LEASE_VERIFY_KEY_ED25519_PUBLIC", "aa" * 32)
    caplog.set_level(logging.INFO, logger=LOGGER)
    assert lease.verify_authenticity(now=DURING) == LeaseVerificationResult(
        False, "signature_algorithm_refused")
    record = _only_event(caplog, "lease.verification_unavailable")
    assert record.levelno == logging.WARNING
    payload = _payload(record)
    assert set(payload) == {"sig_alg", "tenant_id", "tool_name", "detail"}
    assert payload["sig_alg"] == signing.ALG_HMAC
    assert payload["tenant_id"] == TENANT
    assert payload["tool_name"] == TOOL
    assert "HMAC lease signatures are refused" in payload["detail"]


def test_a_missing_key_is_reported_as_unavailable(
        _hmac_research: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    lease = dataclasses.replace(_issue(), sig_alg=signing.ALG_ED25519)
    caplog.set_level(logging.INFO, logger=LOGGER)
    assert lease.verify_authenticity(now=DURING) == LeaseVerificationResult(
        False, "no_signing_key")
    payload = _payload(_only_event(caplog, "lease.verification_unavailable"))
    assert payload["sig_alg"] == signing.ALG_ED25519
    assert "an Ed25519 lease cannot be verified" in payload["detail"]


# -- ExecutionLease.verify ------------------------------------------------------------


def test_an_empty_target_environment_matches_an_empty_binding() -> None:
    """``None`` and ``""`` both mean "no target"; neither is a mismatch."""
    lease = _issue(target_environment="")
    assert _verify(lease, target_environment="") == LeaseVerificationResult(True, "ok")


def test_an_empty_toolspec_check_matches_an_unbound_lease() -> None:
    """Absent on both sides is equal; a named spec against none is not."""
    lease = _issue()
    assert _verify(lease, toolspec_hash="") == LeaseVerificationResult(True, "ok")
    assert _verify(lease, toolspec_hash="spec-1") == LeaseVerificationResult(
        False, "toolspec_hash_mismatch")


def test_a_half_bound_task_is_malformed() -> None:
    half = _resigned(_issue(), task_id="task-a")
    assert _verify(half) == LeaseVerificationResult(False, "task_identity_malformed")


def test_an_unbound_lease_checked_against_a_task_is_task_unbound() -> None:
    assert _verify(_issue(), task_identity=TASK_A) == LeaseVerificationResult(
        False, "task_unbound")


def test_a_lease_for_another_task_is_task_mismatch() -> None:
    lease = _issue(task_identity=TASK_A)
    assert _verify(lease, task_identity=TASK_B) == LeaseVerificationResult(
        False, "task_mismatch")
    assert _verify(lease, task_identity=TASK_A) == LeaseVerificationResult(True, "ok")


# -- ExecutionLease.from_dict ---------------------------------------------------------


def test_from_dict_names_the_unknown_fields() -> None:
    data = {**_issue().to_dict(), "bogus": 1, "another": 2}
    with pytest.raises(ValueError, match=r"^unknown lease fields: \['another', 'bogus'\]$"):
        ExecutionLease.from_dict(data)


# -- dispatcher hooks -----------------------------------------------------------------


def _dispatcher() -> GovernedToolDispatcher:
    return GovernedToolDispatcher(expected_policy_bundle_hash=BUNDLE)


def test_a_lease_naming_no_runtime_is_allowed_and_recorded_outside_strict(
        caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    assert GovernedToolDispatcher._runtime_refusal(_issue()) is None
    record = _only_event(caplog, "dispatch.runtime_unbound")
    assert record.levelno == logging.INFO
    assert _payload(record) == {"tenant_id": TENANT, "tool_name": TOOL,
                                "proposal_id": "prop-1", "grant_jti": "jti-1"}


class _Effect:
    def __init__(self, digest: str) -> None:
        self._digest = digest

    def digest(self) -> str:
        return self._digest


class _Resolver:
    def __init__(self, digest: str = "effect-1", *, fail: bool = False) -> None:
        self.digest, self.fail = digest, fail

    def resolve(self, tool_name: str, arguments: Any, target_environment: str) -> Any:
        if self.fail:
            raise RuntimeError("registry offline")
        return _Effect(self.digest)


def test_an_unchecked_resolved_effect_is_recorded(caplog: pytest.LogCaptureFixture) -> None:
    """A bound effect with no resolver to compare it is allowed outside a
    strict profile, and the event is the only trace that it went unchecked."""
    caplog.set_level(logging.INFO, logger=LOGGER)
    lease = dataclasses.replace(_issue(), resolved_effect_hash="effect-1")
    assert _dispatcher()._effect_refusal(lease, TOOL, ARGS, TARGET) is None
    record = _only_event(caplog, "dispatch.resolved_effect_unchecked")
    assert record.levelno == logging.INFO
    assert _payload(record) == {"tenant_id": TENANT, "tool_name": TOOL,
                                "proposal_id": "prop-1"}


def test_an_unbound_resolved_effect_is_recorded(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    dispatcher = _dispatcher()
    dispatcher.bind_effect_resolver(_Resolver())  # type: ignore[arg-type]
    assert dispatcher._effect_refusal(_issue(), TOOL, ARGS, TARGET) is None
    record = _only_event(caplog, "dispatch.resolved_effect_unbound")
    assert record.levelno == logging.INFO
    assert _payload(record) == {"tenant_id": TENANT, "tool_name": TOOL,
                                "proposal_id": "prop-1"}


def test_a_tool_declared_not_applicable_skips_resolution() -> None:
    """NOT_APPLICABLE is accepted only for read-only specs; the resolver is
    not consulted at all, so its failure cannot refuse the call."""
    dispatcher = _dispatcher()
    dispatcher.bind_binding_policy(BindingPolicy(
        bindings=_all_bindings(resolved_effect="REQUIRED"),
        tools={TOOL: {"resolved_effect": "NOT_APPLICABLE"}}))
    dispatcher.bind_effect_resolver(_Resolver(fail=True))  # type: ignore[arg-type]
    assert dispatcher._effect_refusal(_issue(), TOOL, ARGS, TARGET) is None
    assert dispatcher._effect_refusal(_issue(), "other_tool", ARGS, TARGET) == (
        "resolved_effect_unresolvable")


class _Recorder:
    def __init__(self, *, fail: bool = False) -> None:
        self.appends: list[tuple[str, dict[str, Any]]] = []
        self.fail = fail

    def append(self, stream: str, event: dict[str, Any]) -> RecorderReceipt:
        if self.fail:
            raise RecorderUnavailable("recorder did not confirm")
        self.appends.append((stream, dict(event)))
        return RecorderReceipt(seq=len(self.appends), entry_hash="h")


def _recorded(lease: ExecutionLease, phase: str, **detail: Any) -> dict[str, Any]:
    return {"phase": phase, "tenant_id": TENANT, "tool_name": TOOL,
            "proposal_id": "prop-1", "grant_jti": "jti-1",
            "tool_args_hash": lease.tool_args_hash, "nonce": lease.nonce, **detail}


def test_the_recorder_receives_the_dispatch_identity_on_the_dispatch_stream() -> None:
    """The recorder is the out-of-process join point; its keys are what an
    auditor queries by."""
    recorder = _Recorder()
    dispatcher = _dispatcher()
    dispatcher.bind_recorder(recorder, mandatory_for=lambda tool: tool == TOOL)  # type: ignore[arg-type]
    lease = _issue()
    assert dispatcher._record(lease, TOOL, "intent", extra="x") == 1
    assert dispatcher._record(lease, "other_tool", "intent") is None
    assert recorder.appends == [("dispatch", _recorded(lease, "intent", extra="x"))]


def test_the_outcome_record_names_its_intent() -> None:
    recorder = _Recorder()
    dispatcher = _dispatcher()
    dispatcher.bind_recorder(recorder, mandatory_for=lambda tool: True)  # type: ignore[arg-type]
    lease = _issue()
    dispatcher._record_outcome(lease, TOOL, 7, "executed")
    dispatcher._record_outcome(lease, TOOL, None, "executed")
    assert recorder.appends == [
        ("dispatch", _recorded(lease, "outcome", intent_seq=7, outcome="executed"))]


def test_an_unrecorded_outcome_is_an_error_event(caplog: pytest.LogCaptureFixture) -> None:
    """The effect already happened, so this cannot refuse; the event is all
    that is left."""
    caplog.set_level(logging.INFO, logger=LOGGER)
    dispatcher = _dispatcher()
    dispatcher.bind_recorder(_Recorder(fail=True), mandatory_for=lambda tool: True)  # type: ignore[arg-type]
    dispatcher._record_outcome(_issue(), TOOL, 7, "executed")
    record = _only_event(caplog, "dispatch.recorder_outcome_unrecorded")
    assert record.levelno == logging.ERROR
    assert _payload(record) == {"tenant_id": TENANT, "tool_name": TOOL,
                                "proposal_id": "prop-1", "intent_seq": 7,
                                "outcome": "executed", "detail": "recorder did not confirm"}


_NO_BULK_CLOSE = ProcedureContract(
    "proc-1", (absence(StepPattern(TOOL, {"scope": "all"})),))


def _procedure_dispatcher() -> tuple[GovernedToolDispatcher, list[Any]]:
    seen: list[Any] = []

    def trace_for(lease: ExecutionLease) -> list[Any]:
        seen.append(lease)
        return []

    dispatcher = _dispatcher()
    dispatcher.bind_procedure(_NO_BULK_CLOSE, trace_for)
    return dispatcher, seen


def test_a_procedure_violation_refuses_and_names_the_obligation(
        caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    dispatcher, seen = _procedure_dispatcher()
    lease = _issue()
    assert dispatcher._procedure_refusal(lease, TOOL, {"scope": "all"}) == (
        "procedure_violation")
    assert seen == [lease]
    record = _only_event(caplog, "dispatch.procedure_refused")
    assert record.levelno == logging.WARNING
    assert _payload(record) == {"tenant_id": TENANT, "tool_name": TOOL,
                                "proposal_id": "prop-1", "contract_id": "proc-1",
                                "obligations": ["absence(wo_close(scope=all))"]}


def test_a_procedure_reads_the_arguments_only_when_they_are_a_mapping(
        caplog: pytest.LogCaptureFixture) -> None:
    """A step pattern matches on argument values, so dict arguments must reach
    it and anything else must reach it as no arguments."""
    caplog.set_level(logging.INFO, logger=LOGGER)
    dispatcher, _ = _procedure_dispatcher()
    assert dispatcher._procedure_refusal(_issue(), TOOL, {"scope": "one"}) is None
    assert dispatcher._procedure_refusal(_issue(), TOOL, ["scope", "all"]) is None
    assert _events(caplog, "dispatch.procedure_refused") == []


def _policy_dispatcher() -> tuple[GovernedToolDispatcher, list[tuple[str, bool]]]:
    calls: list[tuple[str, bool]] = []

    def check(tool_name: str, mediated: bool) -> str | None:
        calls.append((tool_name, mediated))
        return "effect_policy_refused"

    dispatcher = _dispatcher()
    dispatcher.bind_binding_policy(BindingPolicy(
        bindings=_all_bindings(effect_mediation="REQUIRED")))
    dispatcher.bind_effect_policy(check)
    dispatcher.register(TOOL, lambda args: "ok", mediated=True)
    dispatcher.register("plain_tool", lambda args: "ok")
    return dispatcher, calls


def test_the_effect_policy_is_asked_about_the_leased_tool_as_registered() -> None:
    dispatcher, calls = _policy_dispatcher()
    assert dispatcher._policy_refusal(_issue()) == "effect_policy_refused"
    assert dispatcher._policy_refusal(
        dataclasses.replace(_issue(), tool_name="plain_tool")) == "effect_policy_refused"
    assert calls == [(TOOL, True), ("plain_tool", False)]
    assert calls[1][1] is False


def _surface_dispatcher(observed: str, *, enforce: bool) -> GovernedToolDispatcher:
    dispatcher = _dispatcher()
    dispatcher.bind_surface_observer(lambda: observed, enforce=enforce)
    return dispatcher


def test_surface_metrics_count_every_comparison() -> None:
    """The shadow-period metrics are cumulative counters."""
    lease = dataclasses.replace(_issue(), surface_digest="surface-a")
    changed = _surface_dispatcher("surface-b", enforce=True)
    for _ in range(3):
        assert changed._surface_refusal(lease) == "surface_changed"
    assert (changed.surface_checks, changed.surface_changes) == (3, 3)
    same = _surface_dispatcher("surface-a", enforce=True)
    for _ in range(2):
        assert same._surface_refusal(lease) is None
    assert (same.surface_checks, same.surface_changes) == (2, 0)


@pytest.mark.parametrize("enforce, refusal", [(True, "surface_changed"), (False, None)])
def test_a_changed_surface_is_recorded_with_whether_it_was_enforced(
        caplog: pytest.LogCaptureFixture, enforce: bool, refusal: str | None) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    lease = dataclasses.replace(_issue(), surface_digest="surface-a")
    assert _surface_dispatcher("surface-b", enforce=enforce)._surface_refusal(lease) == refusal
    record = _only_event(caplog, "dispatch.surface_changed")
    assert record.levelno == logging.WARNING
    assert _payload(record) == {"tenant_id": TENANT, "tool_name": TOOL,
                                "proposal_id": "prop-1", "enforced": enforce}
    assert _payload(record)["enforced"] is enforce


_PLAN = PlanBinding(plan_id="plan-1", reads=(("r1", "v1"), ("r2", "v2")),
                    depends_on=("r1",))


def _plan_dispatcher(revisions: dict[str, str]) -> GovernedToolDispatcher:
    def read(resource: str) -> str:
        return revisions[resource]

    dispatcher = _dispatcher()
    dispatcher.bind_state_revisions(read)
    return dispatcher


def _plan_lease() -> ExecutionLease:
    return dataclasses.replace(_issue(), plan_binding_hash=_PLAN.digest())


def test_a_fresh_plan_passes_without_a_refusal_event(
        caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    dispatcher = _plan_dispatcher({"r1": "v1", "r2": "v9"})
    assert dispatcher._plan_refusal(_plan_lease(), _PLAN) is None
    assert _events(caplog, "dispatch.plan_refused") == []


def test_a_stale_plan_names_the_moved_dependency(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    dispatcher = _plan_dispatcher({"r1": "v9", "r2": "v2"})
    assert dispatcher._plan_refusal(_plan_lease(), _PLAN) == "stale_plan"
    record = _only_event(caplog, "dispatch.plan_refused")
    assert record.levelno == logging.WARNING
    assert _payload(record) == {"tenant_id": TENANT, "tool_name": TOOL,
                                "proposal_id": "prop-1", "plan_id": "plan-1",
                                "reason": "stale_plan", "moved": ["r1"], "unreadable": []}


def test_an_unreadable_plan_dependency_names_the_resource(
        caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER)
    dispatcher = _plan_dispatcher({"r2": "v2"})
    assert dispatcher._plan_refusal(_plan_lease(), _PLAN) == "plan_state_unverifiable"
    assert _payload(_only_event(caplog, "dispatch.plan_refused")) == {
        "tenant_id": TENANT, "tool_name": TOOL, "proposal_id": "prop-1",
        "plan_id": "plan-1", "reason": "plan_state_unverifiable", "moved": [],
        "unreadable": ["r1"]}

