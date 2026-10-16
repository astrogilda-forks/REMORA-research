# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""scripts/test_inventory.py: the test-inventory hash and environment manifest (AS-003)."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import test_inventory as inv  # noqa: E402

SAMPLE = """\
tests/test_a.py::test_one
tests/test_a.py::test_two[x-1]
tests/test_b.py::TestK::test_three

3 tests collected in 0.10s
"""


def test_parse_keeps_only_node_ids():
    assert inv.parse_collect_output(SAMPLE) == [
        "tests/test_a.py::test_one",
        "tests/test_a.py::test_two[x-1]",
        "tests/test_b.py::TestK::test_three",
    ]


def test_hash_is_deterministic():
    ids = inv.parse_collect_output(SAMPLE)
    assert inv.inventory_hash(ids) == inv.inventory_hash(list(ids))
    assert re.fullmatch(r"[0-9a-f]{64}", inv.inventory_hash(ids))


def test_hash_does_not_depend_on_collection_order():
    ids = inv.parse_collect_output(SAMPLE)
    assert inv.inventory_hash(ids) == inv.inventory_hash(list(reversed(ids)))
    assert inv.build_inventory(list(reversed(ids))) == inv.build_inventory(ids)


def test_hash_changes_when_a_node_id_is_added_or_removed():
    ids = inv.parse_collect_output(SAMPLE)
    base = inv.inventory_hash(ids)
    assert inv.inventory_hash(ids + ["tests/test_c.py::test_new"]) != base
    assert inv.inventory_hash(ids[:-1]) != base
    # A duplicated id is a different inventory too.
    assert inv.inventory_hash(ids + [ids[0]]) != base


def test_manifest_has_the_expected_shape_and_no_environment_values():
    secret = "AS003-SECRET-VALUE-9f3a"
    os.environ["AS003_PROBE_TOKEN"] = secret
    try:
        manifest = inv.build_manifest(ROOT)
    finally:
        del os.environ["AS003_PROBE_TOKEN"]
    text = json.dumps(manifest)
    assert secret not in text
    assert set(manifest) == {
        "schema", "python", "platform", "lock_files_sha256", "git_sha", "distributions",
    }
    assert manifest["python"]["version"].count(".") >= 1
    assert manifest["distributions"], "no installed distributions listed"
    assert list(manifest["distributions"]) == sorted(manifest["distributions"])
    assert "requirements-lock.txt" in manifest["lock_files_sha256"]
    for digest in manifest["lock_files_sha256"].values():
        assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_manifest_has_no_host_user_or_path():
    text = json.dumps(inv.build_manifest(ROOT))
    for forbidden in (str(ROOT), str(Path.home()), os.environ.get("USERNAME", "\0"),
                      os.environ.get("USER", "\0"), os.environ.get("COMPUTERNAME", "\0")):
        if len(forbidden) > 3:
            assert forbidden not in text
    manifest = json.loads(text)
    assert "node" not in manifest["platform"] and "hostname" not in manifest["platform"]


def test_manifest_lock_hash_ignores_line_endings(tmp_path):
    (tmp_path / "requirements-lock.txt").write_bytes(b"a==1\r\nb==2\r\n")
    crlf = inv.build_manifest(tmp_path)["lock_files_sha256"]
    (tmp_path / "requirements-lock.txt").write_bytes(b"a==1\nb==2\n")
    assert inv.build_manifest(tmp_path)["lock_files_sha256"] == crlf


def _write(tmp_path, name, ids):
    path = tmp_path / name
    path.write_text(json.dumps(inv.build_inventory(ids)), encoding="utf-8")
    return str(path)


def test_compare_identical_exits_zero(tmp_path, capsys):
    ids = inv.parse_collect_output(SAMPLE)
    a, b = _write(tmp_path, "a.json", ids), _write(tmp_path, "b.json", list(reversed(ids)))
    assert inv.main(["compare", a, b]) == 0
    assert "identical" in capsys.readouterr().out


def test_compare_reports_the_symmetric_difference(tmp_path, capsys):
    ids = inv.parse_collect_output(SAMPLE)
    a = _write(tmp_path, "a.json", ids + ["tests/test_only_a.py::test_x"])
    b = _write(tmp_path, "b.json", ids + ["tests/test_only_b.py::test_y[1]"])
    assert inv.main(["compare", a, b]) == 1
    out = capsys.readouterr().out
    assert "only in first: tests/test_only_a.py::test_x" in out
    assert "only in second: tests/test_only_b.py::test_y[1]" in out


def test_compare_does_not_trust_a_stored_hash(tmp_path):
    ids = inv.parse_collect_output(SAMPLE)
    a = _write(tmp_path, "a.json", ids)
    data = inv.build_inventory(ids + ["tests/test_extra.py::test_z"])
    data["sha256"] = inv.inventory_hash(ids)  # a lying hash
    (tmp_path / "b.json").write_text(json.dumps(data), encoding="utf-8")
    assert inv.main(["compare", a, str(tmp_path / "b.json")]) == 1


def test_marker_expression_matches_pyproject_addopts():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^addopts = "(.*)"$', text, re.MULTILINE)
    assert match, "addopts not found"
    assert f"-m '{inv.MARKER_EXPRESSION}'" in match.group(1)


@pytest.mark.skipif(os.environ.get("AS003_NESTED") == "1", reason="no recursive collection")
def test_collect_matches_this_suite_for_a_narrow_target(monkeypatch):
    """The parser reads real pytest output: collect only this file."""
    import subprocess

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_test_inventory.py", "--collect-only",
         "-q", "-o", "addopts=", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True,
        env={**os.environ, "AS003_NESTED": "1"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    ids = inv.parse_collect_output(proc.stdout)
    assert "tests/test_test_inventory.py::test_hash_is_deterministic" in ids
    assert all(i.startswith("tests/test_test_inventory.py::") for i in ids)
