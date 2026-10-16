# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""scripts/check_test_accounting.py reconciles JUnit XML with pytest's summary.

The fixture pair under tests/data/test_accounting/ is real pytest 8 output
for one test of each outcome: pass, fail, skip, xfail, xpass, a setup error
and a teardown error on a passing test. Two JUnit quirks matter. An xpass
is written as a plain passing testcase, and a teardown error is a testcase
whose test also counts as passed, so the suite's ``tests`` attribute counts
that test twice.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data" / "test_accounting"
SCRIPT = ROOT / "scripts" / "check_test_accounting.py"

sys.path.insert(0, str(ROOT / "scripts"))
import check_test_accounting as acct  # noqa: E402


def test_the_real_output_reconciles():
    account = acct.account(DATA / "pytest8_all_outcomes.xml",
                           DATA / "pytest8_all_outcomes.txt")
    assert account.problems == []
    assert account.junit == {"ok": 2, "failure": 1, "error": 2, "skipped": 1,
                             "xfailed": 1}
    assert account.summary == {"passed": 2, "failed": 1, "skipped": 1, "xfailed": 1,
                               "xpassed": 1, "errors": 2}
    assert account.testcases == 7
    assert account.teardown_errors == 1


@pytest.mark.parametrize(("summary", "needle"), [
    ("1 failed, 2 passed, 1 skipped, 1 xfailed, 1 xpassed, 1 errors in 0.46s", "error"),
    ("1 failed, 2 passed, 2 skipped, 1 xfailed, 1 xpassed, 2 errors in 0.46s", "skipped"),
    ("1 failed, 3 passed, 1 skipped, 1 xfailed, 1 xpassed, 2 errors in 0.46s", "testcases"),
    ("0 failed, 2 passed, 1 skipped, 1 xfailed, 1 xpassed, 2 errors in 0.46s", "failure"),
])
def test_a_summary_that_disagrees_is_a_problem(tmp_path, summary, needle):
    report = tmp_path / "report.txt"
    report.write_text(f"=== short test summary info ===\n{summary}\n", encoding="utf-8")
    account = acct.account(DATA / "pytest8_all_outcomes.xml", report)
    assert any(needle in p for p in account.problems), account.problems


@pytest.mark.parametrize("line", [
    "1 failed, 2 passed in 0.46s",
    "================ 370 passed, 17 deselected, 1 warning in 7.55s ================",
    "== 1030 passed, 60 skipped, 9365 deselected, 1 warning in 116.46s (0:01:56) ===",
])
def test_summary_lines_in_every_pytest_shape_parse(line):
    assert acct._parse_summary_line(line) is not None


def test_a_long_hostile_line_is_rejected_quickly():
    # CodeQL py/redos on the first version: nested quantifiers backtracked on
    # "0 000 000 ...". The parser is linear now.
    import time
    start = time.perf_counter()
    assert acct._parse_summary_line("0 " + "000 " * 50_000 + "x") is None
    assert time.perf_counter() - start < 1.0


def test_a_report_without_a_summary_line_is_a_problem(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text("F.sxXEE   [ 54%]\n", encoding="utf-8")
    account = acct.account(DATA / "pytest8_all_outcomes.xml", report)
    assert any("summary" in p for p in account.problems)


def test_a_testcase_with_two_outcomes_is_a_problem(tmp_path):
    xml = (DATA / "pytest8_all_outcomes.xml").read_text(encoding="utf-8").replace(
        '<skipped type="pytest.xfail" message="known" />',
        '<skipped type="pytest.xfail" message="known" /><failure message="x">x</failure>')
    junit = tmp_path / "j.xml"
    junit.write_text(xml, encoding="utf-8")
    account = acct.account(junit, DATA / "pytest8_all_outcomes.txt")
    assert any("more than one outcome" in p for p in account.problems)


def test_a_junit_file_with_a_dtd_is_refused_unparsed(tmp_path):
    junit = tmp_path / "j.xml"
    junit.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]>'
                     "<testsuites><testsuite><testcase name='t'>&a;</testcase>"
                     "</testsuite></testsuites>", encoding="utf-8")
    account = acct.account(junit, DATA / "pytest8_all_outcomes.txt")
    assert account.testcases == 0
    assert any("DTD" in p for p in account.problems)


def test_the_cli_writes_the_account_and_fails_on_a_problem(tmp_path):
    out = tmp_path / "account.json"
    ok = subprocess.run([sys.executable, str(SCRIPT), str(DATA / "pytest8_all_outcomes.xml"),
                         str(DATA / "pytest8_all_outcomes.txt"), "--json", str(out)],
                        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["testcases"] == 7 and written["problems"] == []

    bad = tmp_path / "bad.txt"
    bad.write_text("1 passed in 0.1s\n", encoding="utf-8")
    fail = subprocess.run([sys.executable, str(SCRIPT), str(DATA / "pytest8_all_outcomes.xml"),
                           str(bad)], capture_output=True, text=True)
    assert fail.returncode == 1
    assert "[FAIL]" in fail.stdout
