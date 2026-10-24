# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The pull-request test selection is conservative and catches known regressions.

``scripts/select_tests_for_change.py`` decides which test files a pull
request runs; a push to master runs everything. These tests pin the rules on
the live repository: the changes that must run the whole suite, the known
regressions a subset must still catch (the Postgres limit ledger of P0 item
8 ran in ``tests/limits``; the registry fixture is loaded through a string),
the document gates, and determinism.
"""
from __future__ import annotations

import pytest

import scripts.select_tests_for_change as sel

pytestmark = pytest.mark.docgate


def _select(*changed: str) -> set[str]:
    files, _ = sel.select(list(changed))
    assert files is not None, "expected a subset, got ALL"
    return set(files)


@pytest.mark.parametrize("path", [
    "pyproject.toml", "requirements-lock.txt", "tests/conftest.py", ".github/workflows/ci.yml",
    "remora/__init__.py", "remora/enforcement/__init__.py", "tests/data/x.txt",
    "deploy/ot-pilot/limits.json", "integrations/horizon55/enforce.py", "frontend/package.json",
    "paper/remora_paper.md", "provenance/concepts/PROV-13.yaml",
])
def test_changes_the_model_does_not_cover_run_the_whole_suite(path):
    files, reasons = sel.select([path])
    assert files is None and "ALL" in reasons, reasons


def test_the_limit_ledger_change_selects_the_limit_suites():
    """P0 item 8 changed remora/enforcement/cumulative_limits.py and was
    proven by tests/limits; a subset that missed them would have passed."""
    selected = _select("remora/enforcement/cumulative_limits.py")
    assert {"tests/limits/test_limits_postgres.py", "tests/limits/test_limits_idempotency.py",
            "tests/limits/test_limits_unit.py",
            "tests/test_horizon55_enforcement_adversarial.py"} <= selected


def test_a_module_loaded_through_a_string_still_selects_its_users():
    """tests/dispatcher_registry_fixture.py is named by REMORA_TOOL_REGISTRY_MODULE
    in test environments, never imported; the text rule finds those tests."""
    selected = _select("tests/dispatcher_registry_fixture.py")
    assert {"tests/test_dispatch_leased_endpoint.py", "tests/flow/test_flow_dispatch_leased.py",
            "tests/test_execution_stop.py"} <= selected


def test_a_changed_test_file_selects_itself():
    assert "tests/test_select_tests_for_change.py" in _select("tests/test_select_tests_for_change.py")


def test_a_register_change_selects_its_gates_and_every_docgate_file():
    selected = _select("docs/assurance/capability_register_v1.yaml")
    assert {"tests/test_capability_register.py", "tests/test_capability_hooks.py",
            "tests/test_remora_boundary_declaration.py"} <= selected
    assert set(sel.docgate_files()) <= selected


def test_a_readme_change_runs_the_docgate_set_and_nothing_is_ever_empty():
    selected = _select("README.md")
    assert selected and set(sel.docgate_files()) <= selected


def test_the_execution_api_reaches_most_of_the_route_suites():
    selected = _select("servers/execution_api.py")
    assert {"tests/test_execution_api.py", "tests/test_dispatch_leased_endpoint.py",
            "tests/flow/test_mediation_surface.py", "tests/test_review_admission_grant_withheld.py",
            "tests/test_execution_stop.py"} <= selected
    # tests/conformance/test_execution_boundary.py drives GovernedToolDispatcher
    # directly and imports nothing from the server: it is rightly not selected.
    assert "tests/conformance/test_execution_boundary.py" not in selected


def test_the_import_graph_sees_from_imports_of_submodules():
    reverse = sel.import_graph()
    assert "tests.limits.test_limits_postgres" in reverse["remora.enforcement.cumulative_limits"]
    assert "servers.execution_api" in reverse["remora.enforcement.lease"]


def test_the_selection_is_deterministic():
    first = sel.select(["remora/flow/labeler.py", "docs/07-api-reference.md"])
    second = sel.select(["docs/07-api-reference.md", "remora/flow/labeler.py"])
    assert first[0] == second[0] and first[0] == sorted(first[0])


def test_every_selected_file_exists_and_is_a_test_file():
    files = _select("remora/enforcement/lease.py")
    for rel in files:
        assert rel.startswith("tests/") and rel.rsplit("/", 1)[-1].startswith("test_"), rel
        assert (sel.ROOT / rel).is_file(), rel
