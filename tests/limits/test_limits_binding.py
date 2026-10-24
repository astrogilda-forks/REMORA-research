# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Cumulative limits bound to the authority that sets them and to every grant.

Three gaps a declared limit left open, pinned here:

* the limit policy was unsigned deployment configuration, tied to no
  authority (signed policies, REMORA_LIMITS_TRUSTED_KEYS);
* an approval given while limits were on could be executed after they were
  turned off or changed, and then ran unbounded (the limit policy is part of
  the policy identity every grant and approval is bound to);
* nothing made limits mandatory (REMORA_REQUIRE_LIMITS).
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from remora.crypto import SignatureDomain, SigningKey  # noqa: E402
from remora.enforcement import cumulative_limits as cl  # noqa: E402
from tests.limits.harness import (  # noqa: E402
    approve_and_execute,
    assess,
    make_client,
    ran,
    refused_at_dispatch,
    run,
)
from tests.limits.test_limits_payments import pay, policy  # noqa: E402
from tests.limits.test_limits_ventilation import policy as ventilation_policy  # noqa: E402

AUTHORITY = SigningKey.generate({SignatureDomain.LIMIT_POLICY})
STRANGER = SigningKey.generate({SignatureDomain.LIMIT_POLICY})


def signed(body, key=AUTHORITY):
    return cl.sign_policy(body, key, "2026-10-23T00:00:00Z")


def trust(monkeypatch, *keys):
    monkeypatch.setenv("REMORA_LIMITS_TRUSTED_KEYS",
                       ",".join(k.verification_key().public_bytes.hex() for k in keys))


def _reset():
    import servers.execution_api as exec_mod

    exec_mod._reset_tool_dispatcher()


# ── a grant is bound to the limits it was decided under ──────────────────


def test_an_approval_does_not_outlive_the_limits_it_was_given_under(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, policy())
    run(client, pay("A"))
    run(client, pay("B"))
    item = assess(client, pay("C", amount=6000)).json()["review_item_id"]  # fits: 20000
    for var in ("REMORA_LIMITS_FILE", "REMORA_LIMITS_LEDGER"):
        monkeypatch.delenv(var)                     # limits turned off after approval
    _reset()
    r = approve_and_execute(client, item, pay("C", amount=6000))
    assert (r.status_code, r.json()["detail"]) == (409, "limits_changed")
    assert [p["reference"] for p in ran(tmp_path)] == ["hs51-musubi-2-A", "hs51-musubi-2-B"]


def test_an_approval_does_not_survive_a_raised_limit(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, policy())
    run(client, pay("A"))
    item = assess(client, pay("B")).json()["review_item_id"]
    (tmp_path / "limits.json").write_text(json.dumps(policy(max_=10 ** 6, limit_id="raised")))
    _reset()
    r = approve_and_execute(client, item, pay("B"))
    assert (r.status_code, r.json()["detail"]) == (409, "limits_changed")
    assert len(ran(tmp_path)) == 1


def test_the_limit_policy_is_part_of_the_policy_identity(monkeypatch, tmp_path):
    import servers.api as api_mod

    make_client(monkeypatch, tmp_path, policy())
    first = api_mod._policy_component_hashes()
    assert first["limits_policy_hash"].startswith("sha256:")
    (tmp_path / "limits.json").write_text(json.dumps(policy(max_=19999, limit_id="other")))
    second = api_mod._policy_component_hashes()
    assert second["policy_hash"] != first["policy_hash"]
    monkeypatch.delenv("REMORA_LIMITS_FILE")
    assert api_mod._policy_component_hashes()["limits_policy_hash"] is None
    assert "cumulative_limits" in api_mod.policy_coverage_block()["covers"]


# ── signed by the authority that sets the budgets ────────────────────────


def test_a_signed_policy_from_a_trusted_authority_is_enforced(monkeypatch, tmp_path):
    trust(monkeypatch, AUTHORITY)
    client = make_client(monkeypatch, tmp_path, signed(policy()))
    assert [run(client, pay(c)).get("executed") for c in "AB"] == [True, True]
    assert run(client, pay("C"))["detail"] == "limit_exceeded"


@pytest.mark.parametrize("case", ["tampered", "stranger", "unsigned", "signed_untrusted"])
def test_a_policy_that_does_not_verify_refuses_at_startup(monkeypatch, tmp_path, case):
    import servers.execution_api as exec_mod

    document = signed(policy(), STRANGER if case == "stranger" else AUTHORITY)
    if case == "tampered":
        document["policy"]["limits"][0]["max"] = 10 ** 6
    if case == "unsigned":
        document = policy()
    make_client(monkeypatch, tmp_path, document)
    if case == "signed_untrusted":
        monkeypatch.delenv("REMORA_LIMITS_TRUSTED_KEYS", raising=False)
    else:
        trust(monkeypatch, AUTHORITY)
    _reset()
    with pytest.raises(ValueError):
        exec_mod._limit_guard()


# ── mandatory ─────────────────────────────────────────────────────────────


def _required(monkeypatch, tmp_path, document, keys=(AUTHORITY,)):
    import servers.execution_api as exec_mod

    if keys:
        trust(monkeypatch, *keys)
    make_client(monkeypatch, tmp_path, document)
    monkeypatch.setenv("REMORA_REQUIRE_LIMITS", "1")
    _reset()
    return exec_mod._limit_guard


def test_required_limits_refuse_a_deployment_without_limits(monkeypatch, tmp_path):
    guard = _required(monkeypatch, tmp_path, None)
    with pytest.raises(ValueError, match="no cumulative limits"):
        guard()


def test_required_limits_refuse_an_unsigned_policy(monkeypatch, tmp_path):
    guard = _required(monkeypatch, tmp_path, ventilation_policy(), keys=())
    with pytest.raises(ValueError, match="TRUSTED_KEYS"):
        guard()


def test_required_limits_refuse_a_policy_that_lets_unmetered_writes_run(monkeypatch, tmp_path):
    guard = _required(monkeypatch, tmp_path, signed(policy()))   # coverage listed
    with pytest.raises(ValueError, match="all_writes"):
        guard()


def test_required_signed_all_writes_limits_run(monkeypatch, tmp_path):
    guard = _required(monkeypatch, tmp_path, signed(ventilation_policy()))
    assert guard().policy.coverage == "all_writes"


# ── mandatory operation keys (SDD unified capability execution, P0 item 2) ─


def _keys_required(monkeypatch, tmp_path, document):
    guard = _required(monkeypatch, tmp_path, document)
    monkeypatch.setenv("REMORA_REQUIRE_IDEMPOTENCY", "1")
    _reset()
    return guard


def test_required_keys_refuse_startup_while_a_metered_write_tool_has_none(monkeypatch, tmp_path):
    guard = _keys_required(monkeypatch, tmp_path, signed(ventilation_policy()))
    with pytest.raises(ValueError, match="REMORA_REQUIRE_IDEMPOTENCY.*set_supply_air_setpoint"):
        guard()


def test_required_keys_let_a_policy_that_keys_every_write_tool_run(monkeypatch, tmp_path):
    body = ventilation_policy()
    body["idempotency"] = {tool: {"key_arguments": ["unit"]} for tool in body["meters"]}
    guard = _keys_required(monkeypatch, tmp_path, signed(body))
    assert guard().require_keys is True
    assert guard().policy.idempotency["start_fan"] == ("unit",)


def test_required_keys_refuse_the_call_when_the_tool_kind_is_unknown(monkeypatch, tmp_path):
    """A tool the startup check could not classify is refused call by call, never assumed."""
    import servers.execution_api as exec_mod

    body = ventilation_policy()
    body["meters"]["mystery_tool"] = [{"quantity": "fan_starts", "kind": "count",
                                       "unit": "starts"}]
    guard = _keys_required(monkeypatch, tmp_path, signed(body))
    monkeypatch.setattr(exec_mod, "_tool_is_write",
                        lambda tool: None if tool == "mystery_tool" else False)
    _reset()
    assert guard().preview(tenant="acme", principal="employee-1", tool_name="mystery_tool",
                           arguments={}) == cl.COVERAGE_UNKNOWN


def test_an_approval_from_before_limits_runs_under_the_limits_in_force(monkeypatch, tmp_path):
    """The safe direction: limits turned on after approval apply at dispatch."""
    client = make_client(monkeypatch, tmp_path, None)
    item = assess(client, pay("A", amount=25000)).json()["review_item_id"]
    (tmp_path / "limits.json").write_text(json.dumps(policy()))
    monkeypatch.setenv("REMORA_LIMITS_FILE", str(tmp_path / "limits.json"))
    monkeypatch.setenv("REMORA_LIMITS_LEDGER", str(tmp_path / "limits-ledger.db"))
    _reset()
    r = approve_and_execute(client, item, pay("A", amount=25000)).json()
    assert r["tool_execution"]["refusal_reason"] == "limit_exceeded"
    assert ran(tmp_path) == []


def test_the_async_worker_refuses_an_approval_whose_limits_changed(monkeypatch, tmp_path):
    import servers.execution_api as exec_mod

    monkeypatch.setenv("REMORA_ASYNC_DISPATCH", "1")
    client = make_client(monkeypatch, tmp_path, policy())
    item = assess(client, pay("A")).json()["review_item_id"]
    r = approve_and_execute(client, item, pay("A"))
    assert r.status_code == 202, r.text
    (tmp_path / "limits.json").write_text(json.dumps(policy(max_=10 ** 6, limit_id="raised")))
    _reset()
    results = exec_mod.dispatch_pending_intents("acme", worker_id="w1")
    assert [r["tool_execution"]["refusal_reason"] for r in results] == ["limits_changed"]
    assert ran(tmp_path) == []


# ── the policy enforced is the policy the grants name ────────────────────
#
# The dispatcher keeps the guard it was built with, while a grant binds the
# digest of the policy file read when it is checked. A file replaced on the
# same path without a restart must not leave the old budget enforced under
# the new identity.


def _swap(tmp_path, document):
    (tmp_path / "limits.json").write_text(json.dumps(document))


def _signed_client(monkeypatch, tmp_path):
    trust(monkeypatch, AUTHORITY)
    client = make_client(monkeypatch, tmp_path, signed(policy()))      # 20000
    assert run(client, pay("A"))["executed"] is True
    return client


@pytest.mark.parametrize("replacement", ["smaller", "larger", "tampered", "stranger"])
def test_a_policy_replaced_without_a_restart_refuses(monkeypatch, tmp_path, replacement):
    client = _signed_client(monkeypatch, tmp_path)
    document = {"smaller": signed(policy(max_=10000, limit_id="smaller")),
                "larger": signed(policy(max_=10 ** 6, limit_id="larger")),
                "tampered": signed(policy()),
                "stranger": signed(policy(max_=10 ** 6), STRANGER)}[replacement]
    if replacement == "tampered":
        document["policy"]["limits"][0]["max"] = 10 ** 6
    _swap(tmp_path, document)
    # B fits the 20000 still held in memory; it must not run under it.
    assert run(client, pay("B")) == {"stage": "assess", "status": 409,
                                     "detail": "limit_policy_changed"}
    assert [p["reference"] for p in ran(tmp_path)] == ["hs51-musubi-2-A"]


def test_the_dispatcher_refuses_once_the_deployed_policy_moved(monkeypatch, tmp_path):
    """The reservation at dispatch holds even where no earlier check runs."""
    import servers.execution_api as exec_mod

    _signed_client(monkeypatch, tmp_path)
    guard = exec_mod._limit_guard()
    _swap(tmp_path, signed(policy(max_=10000, limit_id="smaller")))
    assert guard.governs("read_air_temperature")      # unmetered before: refused now
    assert guard.reserve(tenant="acme", principal="employee-1", tool_name="transfer_payment",
                         arguments=pay("B")["arguments"], operation_id="lease:x",
                         request_hash="h") == cl.POLICY_CHANGED
    assert guard.fence("lease:x") == cl.POLICY_CHANGED
    assert guard.compare("transfer_payment", {}, {}) == cl.POLICY_CHANGED


def test_changed_limit_settings_refuse_like_a_changed_file(monkeypatch, tmp_path):
    client = _signed_client(monkeypatch, tmp_path)
    trust(monkeypatch, AUTHORITY, STRANGER)
    # The assessment builds a guard from the new settings; the dispatcher's
    # guard was built from the old ones, and refuses.
    assert refused_at_dispatch(run(client, pay("B")), "limit_policy_changed")
    assert len(ran(tmp_path)) == 1


def test_a_restart_enforces_the_replacement(monkeypatch, tmp_path):
    client = _signed_client(monkeypatch, tmp_path)
    _swap(tmp_path, signed(policy(max_=5000, limit_id="smaller")))
    _reset()
    assert run(client, pay("B"))["detail"] == "limit_exceeded"         # 7000 > 5000
    assert len(ran(tmp_path)) == 1


def test_the_original_policy_restored_runs_again(monkeypatch, tmp_path):
    client = _signed_client(monkeypatch, tmp_path)
    original = (tmp_path / "limits.json").read_bytes()
    _swap(tmp_path, signed(policy(max_=10 ** 6, limit_id="larger")))
    assert run(client, pay("B"))["detail"] == "limit_policy_changed"
    (tmp_path / "limits.json").write_bytes(original)
    assert run(client, pay("B"))["executed"] is True
    assert run(client, pay("C"))["detail"] == "limit_exceeded"


def test_signed_at_is_unsigned_metadata_bound_by_the_identity(monkeypatch, tmp_path):
    """``signed_at`` is outside the signature; the file digest still covers it."""
    import servers.api as api_mod

    document = signed(policy())
    document["signed_at"] = "1999-01-01T00:00:00Z"
    assert cl.verify_signed_policy(document, [AUTHORITY.verification_key()])[0] == policy()
    client = _signed_client(monkeypatch, tmp_path)
    before = api_mod._policy_component_hashes()["limits_policy_hash"]
    _swap(tmp_path, document)
    assert api_mod._policy_component_hashes()["limits_policy_hash"] != before
    assert run(client, pay("B"))["detail"] == "limit_policy_changed"


# ── the replacement, in every order of initialisation ────────────────────


def _replace_policy(tmp_path, max_, limit_id):
    (tmp_path / "limits.json").write_text(json.dumps(signed(policy(max_=max_,
                                                                   limit_id=limit_id))))


@pytest.mark.parametrize("initialised", ["guard_and_dispatcher", "guard_only", "nothing"])
def test_a_replaced_signed_limit_never_lets_a_call_past_the_new_limit(monkeypatch, tmp_path,
                                                                      initialised):
    """A signed 20000 limit is replaced by a valid signed 10000 limit without a
    restart. A 15000 payment must never reach the tool, whichever parts of
    REMORA had already loaded the old policy."""
    import servers.execution_api as exec_mod

    trust(monkeypatch, AUTHORITY)
    client = make_client(monkeypatch, tmp_path, signed(policy(max_=20000, limit_id="b-20000")))
    if initialised == "guard_and_dispatcher":
        assert run(client, pay("A", amount=1000))["executed"] is True
    elif initialised == "guard_only":
        exec_mod._DISPATCHER = None
        assert exec_mod._limit_guard().policy.limits[0].max == 20000
    _replace_policy(tmp_path, 10000, "b-10000")
    outcome = run(client, pay("B", amount=15000))
    assert outcome.get("executed") is not True, outcome
    assert [p["reference"] for p in ran(tmp_path) if p["amount"] == 15000] == []
