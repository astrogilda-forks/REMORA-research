# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The skip-reason gate: a skip nobody wrote down fails the job.

A skipped test is a test that did not run. The gate makes every skip in the
CI pytest job name a listed reason, so a new silent skip (a dependency that
fell out of the install set, a tool that went missing, an artifact that was
never committed) is a reviewed diff. These tests pin the gate's contract and
the shape of the committed allowlist.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_skip_reasons.py"


@pytest.fixture(scope="module")
def gate():
    spec = importlib.util.spec_from_file_location("skip_reasons", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: the script's dataclasses resolve their
    # postponed annotations through sys.modules[module.__name__].
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def entries(gate):
    return gate.load_allowlist()[1]


def _report(*skips: tuple[int, str, str], summary: int | None = None) -> str:
    lines = [f"SKIPPED [{n}] {where}: {reason}" for n, where, reason in skips]
    if summary is not None:
        lines.append(f"= 10 passed, {summary} skipped, 2 deselected in 1.00s =")
    return "\n".join(lines) + "\n"


def test_an_unlisted_reason_fails_and_is_named(gate, entries) -> None:
    code, out = gate.check(_report((1, "tests/test_a.py:12", "node not available"),
                                   (3, "tests/test_b.py:40", "some new reason"), summary=4), entries)
    assert code == 1
    assert any("tests/test_b.py:40: some new reason" in line for line in out)
    assert any(line.startswith("[FAIL]") for line in out)


def test_listed_reasons_pass_and_are_counted_per_class(gate, entries) -> None:
    code, out = gate.check(_report((12, "tests/test_a.py:12", "node not available"),
                                   (2, "tests/test_c.py:5", "could not import 'psycopg': No module named 'psycopg'"),
                                   summary=14), entries)
    assert code == 0, out
    assert any("class external_tool" in line and "12" in line for line in out)
    assert any("class other_job" in line and "2" in line for line in out)
    assert out[-1].startswith("[OK]")


def test_a_report_whose_lines_do_not_add_up_fails(gate, entries) -> None:
    """A truncated or reformatted report must not pass as clean."""
    code, out = gate.check(_report((1, "tests/test_a.py:12", "node not available"), summary=5), entries)
    assert code == 1
    assert "summary says 5" in out[0]


def test_no_skips_is_a_pass(gate, entries) -> None:
    code, out = gate.check("= 10 passed in 1.00s =\n", entries)
    assert code == 0
    assert out == ["[OK] no skipped tests in this report"]


def test_the_cli_reads_a_file(gate, tmp_path, capsys) -> None:
    f = tmp_path / "report.txt"
    f.write_text(_report((1, "tests/test_a.py:12", "node not available"), summary=1), encoding="utf-8")
    assert gate.main(["check_skip_reasons.py", str(f)]) == 0
    assert "[OK]" in capsys.readouterr().out
    assert gate.main(["check_skip_reasons.py"]) == 2


# ── the committed allowlist ────────────────────────────────────────────────


def test_every_entry_has_a_declared_class_and_a_note(gate) -> None:
    classes, entries = gate.load_allowlist()
    assert classes
    for e in entries:
        assert e.cls in classes
        assert e.note.strip()


def test_no_entry_is_a_catch_all(gate, entries) -> None:
    """A pattern that matches an arbitrary new reason would make the gate decorative."""
    for probe in ("zz new reason 4711", "could not import 'fastapi': No module named 'fastapi'",
                  "could not import 'cryptography': No module named 'cryptography'",
                  "could not import 'httpx': No module named 'httpx'",
                  "could not import 'yaml': No module named 'yaml'",
                  "BLOCKED: TLC jar digest changed",
                  "java not found: TLA+ models NOT checked"):
        hit = gate.match(probe, entries)
        assert hit is None, f"{probe!r} matched {hit.pattern.pattern!r}"


def test_every_static_skip_reason_in_the_suite_is_listed_or_deliberately_not(gate, entries) -> None:
    """Every literal reason in tests/ either matches an entry or is one of the
    reasons the allowlist leaves out on purpose (an installed dependency, the
    TLA BLOCKED failure). A new literal skip reason therefore needs an entry
    before it can reach CI."""
    # "; " is the join separator in test_generator_imports.py; its reason ends
    # in ", not installed here", which the extractor sees as a literal too.
    # A runner without Java must fail the TLA+ check, not skip it (the ubuntu
    # image ships a JDK), so that reason stays off the list as well.
    deliberately_unlisted = {"BLOCKED: ", "; ", "java not found: TLA+ models NOT checked"}
    installed = {"fastapi", "cryptography", "httpx", "yaml", "jsonschema", "uvicorn",
                 "cryptography.hazmat.primitives.asymmetric.ed25519"}
    pat = re.compile(r"(?:pytest\.skip\(|pytest\.mark\.skip\(\s*reason\s*=\s*|skipif\([^)]*?reason\s*=\s*)\s*(?P<f>f?)[\"']([^\"']+)[\"']")
    imports = re.compile(r"importorskip\(\s*[\"']([^\"']+)[\"']")
    missing: list[str] = []
    for p in sorted((ROOT / "tests").rglob("test_*.py")) + [ROOT / "tests" / "conftest.py"]:
        text = p.read_text(encoding="utf-8", errors="replace")
        for m in imports.finditer(text):
            name = m.group(1)
            if name in installed:
                continue
            probe = f"could not import '{name}': No module named '{name}'"
            if gate.match(probe, entries) is None:
                missing.append(f"{p.name}: {probe}")
        for m in pat.finditer(text):
            reason = m.group(2)
            if reason in deliberately_unlisted or "{" in reason and m.group("f"):
                continue  # f-strings are matched by their pattern entries at run time
            if gate.match(reason, entries) is None:
                missing.append(f"{p.name}: {reason}")
    assert not missing, "literal skip reasons with no allowlist entry:\n" + "\n".join(missing)
