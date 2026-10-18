# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""agent-control redeems an approved canonical review item (RMR-AUD-010).

With the canonical execution service bound, a write tool is assessed by
REMORA and a VERIFY comes back as 402 with a review item. There was no way to
redeem that item: every retry, with or without the review item id, ran assess
again, opened a new review item and answered 402 again, so an approved write
could never run.

Executes the REAL adapter (esbuild + node) against a fake canonical service
that keeps review state: assess opens an item, a person approves it, and
execute runs it only when it is approved and the call is the one assessed.
Also pins that the approval hash ignores argument order and binds the tool,
tenant and target.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WORKER_DIR = _REPO_ROOT / "workers" / "agent-control"

_DRIVER = """
import { runViaCanonicalService } from ADAPTER;
import { approvalBindingHash } from INDEX;

const results = {};
const ARGS = {key: "a.md", content: "x"};

function fakeService() {
  const items = new Map();
  const calls = [];
  let n = 0;
  const env = {
    EXECUTION_API_TOKEN: "tok",
    EXECUTION_SERVICE: { fetch: async (url, init) => {
      const body = JSON.parse(init.body);
      calls.push({ path: new URL(url).pathname, body });
      const path = new URL(url).pathname;
      if (path === "/v1/execution/assess") {
        const id = "ri-" + (++n);
        items.set(id, { call: JSON.stringify(body), approved: false, outcome: null });
        return new Response(JSON.stringify({ decision: "verify", proposal_id: "p-" + n,
                                             review_item_id: id }), { status: 200 });
      }
      if (path === "/v1/execution/execute") {
        const item = items.get(body.item_id);
        if (!item) return new Response(JSON.stringify({ detail: "not found" }), { status: 404 });
        if (item.outcome) {
          return new Response(JSON.stringify({ outcome: item.outcome, proposal_id: "p-1" }),
                              { status: 200 });
        }
        if (!item.approved) {
          return new Response(JSON.stringify({ detail: "item not approved" }), { status: 409 });
        }
        if (JSON.stringify(body.tool_call) !== item.call) {
          return new Response(JSON.stringify({ outcome: "binding_refused" }), { status: 200 });
        }
        items.delete(body.item_id);
        return new Response(JSON.stringify({ outcome: "execute", proposal_id: "p-1",
          tool_execution: { executed: true, result: { stored: true } } }), { status: 200 });
      }
      return new Response("{}", { status: 404 });
    } },
  };
  return { env, items, calls };
}

// The roundtrip: 402 with a review item, approval, redeem, executed.
{
  const svc = fakeService();
  const first = await runViaCanonicalService(svc.env, "store_artifact", ARGS, "cf", undefined);
  const waiting = await runViaCanonicalService(svc.env, "store_artifact", ARGS, "cf",
                                               first.review_item_id);
  svc.items.get(first.review_item_id).approved = true;
  const second = await runViaCanonicalService(svc.env, "store_artifact", ARGS, "cf",
                                              first.review_item_id);
  const replay = await runViaCanonicalService(svc.env, "store_artifact", ARGS, "cf",
                                              first.review_item_id);
  results.roundtrip = { first, waiting, second, replay,
    assess_count: svc.calls.filter((c) => c.path.endsWith("/assess")).length,
    execute_body: svc.calls.find((c) => c.path.endsWith("/execute"))?.body };
}

// Changed arguments under an approved item are refused, never executed.
{
  const svc = fakeService();
  const first = await runViaCanonicalService(svc.env, "store_artifact", ARGS, "cf", undefined);
  svc.items.get(first.review_item_id).approved = true;
  results.changed = await runViaCanonicalService(
    svc.env, "store_artifact", { ...ARGS, content: "other" }, "cf", first.review_item_id);
}

// A lapsed approval goes back to review under the SAME item.
for (const outcome of ["approval_invalidated", "approval_expired"]) {
  const svc = fakeService();
  const first = await runViaCanonicalService(svc.env, "store_artifact", ARGS, "cf", undefined);
  svc.items.get(first.review_item_id).outcome = outcome;
  results[outcome] = await runViaCanonicalService(svc.env, "store_artifact", ARGS, "cf",
                                                  first.review_item_id);
  results[outcome + "_assess_count"] =
    svc.calls.filter((c) => c.path.endsWith("/assess")).length;
}

// A transport failure while redeeming is unknown and is not retried.
{
  let attempts = 0;
  const env = { EXECUTION_API_TOKEN: "tok", EXECUTION_SERVICE: { fetch: async () => {
    attempts++; throw new Error("reset"); } } };
  results.redeem_unreachable = await runViaCanonicalService(env, "store_artifact", ARGS,
                                                            "cf", "ri-1");
  results.redeem_attempts = attempts;
}

results.hash_order = [
  await approvalBindingHash("store_artifact", {key: "a", content: "b"}, "t1", "cf"),
  await approvalBindingHash("store_artifact", {content: "b", key: "a"}, "t1", "cf"),
];
results.hash_binds = [
  await approvalBindingHash("store_artifact", ARGS, "t1", "cf"),
  await approvalBindingHash("other_tool", ARGS, "t1", "cf"),
  await approvalBindingHash("store_artifact", ARGS, "t2", "cf"),
  await approvalBindingHash("store_artifact", ARGS, "t1", "prod"),
];
results.hash_ignores_control_fields = [
  await approvalBindingHash("store_artifact", ARGS, "t1", "cf"),
  await approvalBindingHash("store_artifact", {...ARGS, audit_id: 7, review_item_id: "ri-1"},
                            "t1", "cf"),
];
console.log(JSON.stringify(results));
"""


@pytest.fixture(scope="module")
def outcome(tmp_path_factory: pytest.TempPathFactory) -> dict:
    if shutil.which("node") is None:
        pytest.skip("node not available")
    if not (_WORKER_DIR / "node_modules" / "esbuild").exists():
        pytest.skip("esbuild not installed in workers/agent-control")
    tmp = tmp_path_factory.mktemp("canonical_redeem")
    bundles = {}
    for name, src in (("adapter", "execution_adapter.ts"), ("index", "index.ts")):
        out = tmp / f"{name}.mjs"
        subprocess.run(
            ["npx", "esbuild", str(_WORKER_DIR / "src" / src), "--bundle",
             "--format=esm", "--platform=node", f"--outfile={out}"],
            cwd=_WORKER_DIR, check=True, capture_output=True, shell=os.name == "nt")
        bundles[name] = out
    driver = tmp / "driver.mjs"
    driver.write_text(
        _DRIVER.replace("ADAPTER", json.dumps(bundles["adapter"].as_uri()))
               .replace("INDEX", json.dumps(bundles["index"].as_uri())),
        encoding="utf-8")
    result = subprocess.run(["node", str(driver)], cwd=_WORKER_DIR, check=True,
                            capture_output=True, text=True)
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_an_approved_review_item_is_redeemed_and_runs(outcome: dict) -> None:
    r = outcome["roundtrip"]
    assert r["first"]["executed"] is False
    assert r["first"]["review_item_id"] == "ri-1"
    assert r["second"]["executed"] is True
    assert r["second"]["result"] == {"stored": True}
    # Redeeming never opened another review item.
    assert r["assess_count"] == 1
    assert r["execute_body"]["item_id"] == "ri-1"
    assert r["execute_body"]["tool_call"]["arguments"] == {"key": "a.md", "content": "x"}


def test_an_unapproved_item_keeps_waiting_on_the_same_item(outcome: dict) -> None:
    w = outcome["roundtrip"]["waiting"]
    assert w["executed"] is False
    assert w["review_item_id"] == "ri-1"
    assert w["refusal_reason"] == "canonical_review_required"


def test_a_redeemed_item_cannot_run_twice(outcome: dict) -> None:
    replay = outcome["roundtrip"]["replay"]
    assert replay["executed"] is False
    assert replay["refusal_reason"] == "canonical_execute_refused:404"


def test_changed_arguments_are_refused(outcome: dict) -> None:
    changed = outcome["changed"]
    assert changed["executed"] is False
    assert changed["refusal_reason"] == "canonical_binding_refused"
    assert "review_item_id" not in changed


@pytest.mark.parametrize("lapse", ["approval_invalidated", "approval_expired"])
def test_a_lapsed_approval_returns_to_the_same_review_item(outcome: dict, lapse: str) -> None:
    r = outcome[lapse]
    assert r["executed"] is False
    assert r["review_item_id"] == "ri-1"
    assert r["refusal_reason"] == "canonical_review_required"
    assert outcome[lapse + "_assess_count"] == 1


def test_a_lost_redeem_is_unknown_and_never_retried(outcome: dict) -> None:
    r = outcome["redeem_unreachable"]
    assert r["executed"] is False
    assert r["refusal_reason"] == "canonical_execute_unreachable_state_unknown"
    assert outcome["redeem_attempts"] == 1


def test_the_approval_hash_ignores_argument_order(outcome: dict) -> None:
    a, b = outcome["hash_order"]
    assert a == b


def test_the_approval_hash_binds_tool_tenant_and_target(outcome: dict) -> None:
    hashes = outcome["hash_binds"]
    assert len(set(hashes)) == 4


def test_the_approval_hash_ignores_control_fields(outcome: dict) -> None:
    a, b = outcome["hash_ignores_control_fields"]
    assert a == b
