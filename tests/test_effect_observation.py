# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The effect observer reports what an implementation reached, and what it could not see.

Slice 1 of docs/design/effect-contract-verification-v1.md. One fixture tool
per effect class, each run in a fresh interpreter under audit hooks. The
tests pin both halves of the observer's honesty: every class it claims to see
is seen, and every way it can be blinded is reported as blinding rather than
dropped. An observer that returned nothing for a tool it could not see would
make that tool look clean.
"""
from __future__ import annotations

import os
import socket
import tempfile
from pathlib import Path

import pytest

from remora.toolcall.effect_observation import BLINDING, EFFECT_CLASSES, observe

TOOLS = Path(__file__).resolve().parent / "fixtures" / "effect_tools"


def _interpreter_can_import_under_a_hook() -> str:
    """'' when a child interpreter imports normally with an audit hook installed.

    CPython 3.14.0 on one Windows development machine breaks module import as
    soon as any audit hook exists (marshal and atomic-write errors); 3.12,
    3.13 and 3.14.8 on Linux do not. On such an interpreter the observer
    cannot run at all, which is a reason to skip, never a result.
    """
    import subprocess
    import sys

    code = ("import sys; sys.addaudithook(lambda e, a: None); "
            f"sys.path.insert(0, {str(TOOLS)!r}); import tools")
    proc = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True)
    return "" if proc.returncode == 0 else (proc.stderr.strip().splitlines() or ["?"])[-1]


_BROKEN = _interpreter_can_import_under_a_hook()
pytestmark = pytest.mark.skipif(
    bool(_BROKEN), reason=f"this interpreter cannot import under an audit hook: {_BROKEN}")


def _run(function: str, *cases, module: str = "tools", timeout_s: float = 60.0):
    return observe(module, function, list(cases), path=[str(TOOLS)], timeout_s=timeout_s)


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_a_clean_read_reaches_nothing_and_is_not_blinded(tmp_path: Path) -> None:
    target = tmp_path / "in.txt"
    target.write_text("hello", encoding="utf-8")
    obs = _run("clean_read", {"path": str(target)})
    (case,) = obs.cases
    assert case.completed and not case.blinded
    assert case.effects == ()
    assert case.reads >= 1


def test_a_file_write_is_seen_with_its_path(tmp_path: Path) -> None:
    (case,) = _run("writes_temp_file", {"dir": str(tmp_path)}).cases
    assert case.effect_classes == {"fs.write"}
    assert any(detail.endswith("scratch.txt") for _, detail in case.effects)


def test_delete_rename_and_mkdir_are_distinct_classes(tmp_path: Path) -> None:
    (case,) = _run("deletes_and_renames", {"dir": str(tmp_path)}).cases
    assert {"fs.write", "fs.rename", "fs.delete", "fs.mkdir"} <= case.effect_classes


def test_a_process_start_is_seen(tmp_path: Path) -> None:
    """The adapter that prompted the design started a worker on every call."""
    (case,) = _run("spawns_process", {}).cases
    assert "process.spawn" in case.effect_classes


def test_a_connection_attempt_is_seen_even_when_it_fails() -> None:
    (case,) = _run("connects_socket", {"port": _closed_port()}).cases
    assert "net.connect" in case.effect_classes


def test_name_resolution_is_reported_apart_from_a_connection() -> None:
    (case,) = _run("resolves_name", {}).cases
    assert case.effect_classes == {"net.resolve"}


def test_an_environment_write_is_seen() -> None:
    (case,) = _run("writes_environment", {}).cases
    assert case.effect_classes == {"env.write"}


def test_native_code_blinds_the_case_instead_of_passing_it() -> None:
    (case,) = _run("uses_ctypes", {}).cases
    assert case.blinded is True
    assert "native_code" in {b for b, _ in case.blinding}


def test_a_tool_installing_its_own_hook_is_reported_as_tampering() -> None:
    (case,) = _run("installs_audit_hook", {}).cases
    assert ("observer_tampering", "the tool installed an audit hook") in case.blinding


def test_an_effect_at_import_is_recorded_in_the_load_phase() -> None:
    marker = Path(tempfile.gettempdir()) / "remora_effect_import_write.txt"
    try:
        obs = _run("tool", {}, module="import_write")
        assert "fs.write" in obs.load.effect_classes
        assert obs.cases[0].effects == ()
    finally:
        marker.unlink(missing_ok=True)


def test_an_effect_on_one_input_only_is_seen_only_on_that_input(tmp_path: Path) -> None:
    """Why slice 3 generates cases from the schema: one author case misses this."""
    obs = _run("writes_only_for_one_value", {"dir": str(tmp_path), "mode": "read"},
               {"dir": str(tmp_path), "mode": "write"})
    assert [c.effect_classes for c in obs.cases] == [frozenset(), frozenset({"fs.write"})]


def test_a_raising_tool_still_reports_what_it_did_first(tmp_path: Path) -> None:
    (case,) = _run("raises", {}).cases
    assert case.completed is True and case.raised == "RuntimeError"


def test_a_timeout_is_blinding_on_every_phase_never_a_clean_run() -> None:
    obs = _run("sleeps", {"seconds": 30}, {"seconds": 30}, timeout_s=5.0)
    assert obs.load.blinded and all(c.blinded for c in obs.cases)
    assert {b for c in obs.cases for b, _ in c.blinding} == {"timeout"}


def test_a_module_that_does_not_import_blinds_its_cases() -> None:
    obs = _run("tool", {}, module="does_not_exist")
    assert obs.load.completed is False
    assert obs.cases and all(c.blinded for c in obs.cases)


def test_the_observer_does_not_report_its_own_work(tmp_path: Path) -> None:
    """Writing the result and importing the harness must not show up as the tool's effects."""
    target = tmp_path / "in.txt"
    target.write_text("x", encoding="utf-8")
    obs = _run("clean_read", {"path": str(target)})
    assert obs.load.effects == () and obs.cases[0].effects == ()


def test_the_vocabulary_is_closed() -> None:
    assert set(EFFECT_CLASSES) == {"fs.write", "fs.delete", "fs.rename", "fs.mkdir",
                                   "process.spawn", "net.connect", "net.resolve", "env.write"}
    assert set(BLINDING) == {"native_code", "observer_tampering", "timeout", "crash"}


def test_the_record_names_its_vantage_and_interpreter(tmp_path: Path) -> None:
    target = tmp_path / "in.txt"
    target.write_text("x", encoding="utf-8")
    record = _run("clean_read", {"path": str(target)}).as_dict()
    assert record["vantage"] == "python_audit_hook"
    assert record["interpreter"].split()[0] == "cpython"
    assert record["platform"] == os.sys.platform


@pytest.mark.skipif(os.name != "nt" and not Path("/proc").exists(), reason="no process model")
def test_the_child_does_not_inherit_a_startup_script(tmp_path: Path, monkeypatch) -> None:
    script = tmp_path / "startup.py"
    script.write_text("open(r'%s', 'w').close()\n" % (tmp_path / "leak.txt"), encoding="utf-8")
    monkeypatch.setenv("PYTHONSTARTUP", str(script))
    target = tmp_path / "in.txt"
    target.write_text("x", encoding="utf-8")
    _run("clean_read", {"path": str(target)})
    assert not (tmp_path / "leak.txt").exists()
