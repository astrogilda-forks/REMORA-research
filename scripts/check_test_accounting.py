#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Reconcile the JUnit XML of a pytest run with pytest's own summary line.

SDD-AS-v1 AS-002 asks that a clean run accounts for every collected test:
pass, fail, error and skip, with no outcome unclassified. The CI pytest job
already fails on a failed test and, through check_skip_reasons.py, on an
unlisted skip reason. What it lacked was a machine-readable record of the
whole run and a check that the record is complete, so a truncated or
partial report cannot pass as a clean one.

This script reads both outputs of one run::

    python -m pytest tests/ -q -rs --junitxml=pytest-junit.xml | tee pytest-report.txt
    python scripts/check_test_accounting.py pytest-junit.xml pytest-report.txt \
        --json test-accounting.json

Each JUnit testcase is classified into exactly one outcome (ok, failure,
error, skipped, xfailed); a testcase carrying two is a problem. The counts
must match the summary line. Two JUnit quirks are allowed for, because
pytest 8 writes them on purpose: an xpass is a plain testcase like a pass,
and an error in teardown sits on a testcase whose test pytest also counts as
passed. Any mismatch is printed and exits 1. The JSON account is written
either way, so the uploaded artifact shows what was counted.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

_SUMMARY = re.compile(r"^=*\s*((?:\d+ \w+(?:, )?)+) in [\d.]+s")
_COUNT = re.compile(r"(\d+) (\w+)")
_SUMMARY_KEYS = {"passed", "failed", "skipped", "xfailed", "xpassed", "errors", "error",
                 "deselected", "warnings", "warning"}


@dataclass
class Account:
    testcases: int = 0
    teardown_errors: int = 0
    junit: dict[str, int] = field(default_factory=dict)
    summary: dict[str, int] = field(default_factory=dict)
    deselected: int = 0
    problems: list[str] = field(default_factory=list)


def _outcome(case: ET.Element) -> list[str]:
    found = []
    for child in case:
        if child.tag == "failure":
            found.append("failure")
        elif child.tag == "error":
            found.append("error")
        elif child.tag == "skipped":
            found.append("xfailed" if child.get("type") == "pytest.xfail" else "skipped")
    return found or ["ok"]


def _summary(report: Path) -> dict[str, int] | None:
    line = None
    for raw in report.read_text(encoding="utf-8", errors="replace").splitlines():
        if _SUMMARY.match(raw.strip()):
            line = raw.strip()
    if line is None:
        return None
    counts: dict[str, int] = {}
    for number, word in _COUNT.findall(line.split(" in ")[0]):
        if word not in _SUMMARY_KEYS:
            return None
        key = {"error": "errors", "warning": "warnings"}.get(word, word)
        counts[key] = int(number)
    return counts


def account(junit: Path, report: Path) -> Account:
    acc = Account()
    data = junit.read_bytes()
    # pytest never writes a DTD. Refusing one before parsing rules out entity
    # expansion and external entities without a third-party parser.
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        acc.problems.append(f"{junit} declares a DTD or entity; refusing to parse it")
        return acc
    root = ET.fromstring(data)
    outcomes: Counter[str] = Counter()
    for case in root.iter("testcase"):
        found = _outcome(case)
        if len(found) > 1:
            acc.problems.append(
                f"testcase {case.get('classname')}::{case.get('name')} has more than one "
                f"outcome: {found}")
        outcomes[found[0]] += 1
        acc.testcases += 1
        for child in case:
            if child.tag == "error" and (child.get("message") or "").startswith(
                    "failed on teardown"):
                acc.teardown_errors += 1
    acc.junit = dict(sorted(outcomes.items()))

    summary = _summary(report)
    if summary is None:
        acc.problems.append(f"no pytest summary line found in {report}")
        return acc
    acc.deselected = summary.pop("deselected", 0)
    summary.pop("warnings", None)
    acc.summary = summary

    def check(what: str, junit_n: int, summary_n: int) -> None:
        if junit_n != summary_n:
            acc.problems.append(f"{what}: JUnit {junit_n}, pytest summary {summary_n}")

    check("failure", outcomes["failure"], summary.get("failed", 0))
    check("error", outcomes["error"], summary.get("errors", 0))
    check("skipped", outcomes["skipped"], summary.get("skipped", 0))
    check("xfailed", outcomes["xfailed"], summary.get("xfailed", 0))
    # A plain testcase is a pass or an xpass; a teardown error's test is in
    # "passed" too, but its testcase was classified as an error above.
    check("ok (passed + xpassed - teardown errors)", outcomes["ok"],
          summary.get("passed", 0) + summary.get("xpassed", 0) - acc.teardown_errors)
    check("testcases", acc.testcases, sum(summary.values()) - acc.teardown_errors)
    return acc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("junit", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--json", type=Path, help="write the account here")
    args = parser.parse_args(argv)

    acc = account(args.junit, args.report)
    if args.json:
        args.json.write_text(json.dumps(asdict(acc), indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
    print(f"testcases {acc.testcases} | JUnit {acc.junit} | summary {acc.summary} | "
          f"deselected {acc.deselected} | teardown errors {acc.teardown_errors}")
    if acc.problems:
        for problem in acc.problems:
            print(f"[FAIL] {problem}")
        return 1
    print("[PASS] every collected test has exactly one outcome, and JUnit agrees "
          "with the pytest summary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
