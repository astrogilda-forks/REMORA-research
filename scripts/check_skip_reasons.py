#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Fail the test job on a skip reason nobody has written down.

A skipped test reports nothing and fails nothing. The TLA+ model checks ran
that way for weeks in 2026-10: the pinned TLC jar's digest had changed, the
tests skipped, and the job stayed green until #834 made a blocked check a
failure. This gate covers the general case. The CI pytest job runs with
``-rs``, and the reason on every ``SKIPPED`` line must match one entry of
``docs/assurance/skip_reason_allowlist_v1.yaml``. An entry says what the skip
depends on (an optional dependency, an external tool, another CI job, a
committed artifact, the platform, a conditional in the data, a live service)
and why that is acceptable in the job that ran. A reason that matches no
entry fails the job and is printed, so a new silent skip is a reviewed diff
and not a surprise.

The gate does not count: a listed reason may fire once or a hundred times.
It prints the number of skipped tests per class, so the job log shows how
much of the suite did not run and why. It also checks that the ``SKIPPED``
lines add up to the ``N skipped`` figure in pytest's summary, so a truncated
or reformatted report cannot pass as a clean one.

Input is the pytest output::

    python -m pytest tests/ -q -rs | tee pytest-report.txt
    python scripts/check_skip_reasons.py pytest-report.txt

Report lines have the form ``SKIPPED [n] path:line: reason``.
"""
from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "docs" / "assurance" / "skip_reason_allowlist_v1.yaml"
SCHEMA = "skip-reason-allowlist/v1"

_SKIP = re.compile(r"^SKIPPED \[(\d+)\] (.+?:\d+): (.*)$")
_SUMMARY = re.compile(r"(\d+) skipped")


@dataclass(frozen=True)
class Skip:
    count: int
    where: str
    reason: str


@dataclass(frozen=True)
class Entry:
    pattern: re.Pattern[str]
    cls: str
    note: str


def parse_report(text: str) -> tuple[list[Skip], int | None]:
    """``SKIPPED`` lines and the summary's skipped figure (None if absent)."""
    skips: list[Skip] = []
    summary: int | None = None
    for line in text.splitlines():
        m = _SKIP.match(line.rstrip())
        if m:
            skips.append(Skip(int(m.group(1)), m.group(2), m.group(3).strip()))
            continue
        if line.startswith("=") and ("passed" in line or "failed" in line or "skipped" in line):
            s = _SUMMARY.search(line)
            if s:
                summary = int(s.group(1))
    return skips, summary


def load_allowlist(path: Path = ALLOWLIST) -> tuple[dict[str, str], list[Entry]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != SCHEMA:
        raise ValueError(f"{path}: unexpected schema_version {data.get('schema_version')!r}")
    classes = dict(data["classes"])
    entries: list[Entry] = []
    for raw in data["entries"]:
        cls = raw["class"]
        if cls not in classes:
            raise ValueError(f"{path}: entry {raw['pattern']!r} has unknown class {cls!r}")
        if not str(raw.get("note", "")).strip():
            raise ValueError(f"{path}: entry {raw['pattern']!r} has no note")
        entries.append(Entry(re.compile(raw["pattern"]), cls, raw["note"]))
    return classes, entries


def match(reason: str, entries: list[Entry]) -> Entry | None:
    for e in entries:
        if e.pattern.fullmatch(reason):
            return e
    return None


def check(text: str, entries: list[Entry]) -> tuple[int, list[str]]:
    """Exit code and the lines to print."""
    skips, summary = parse_report(text)
    lines: list[str] = []
    total = sum(s.count for s in skips)
    if summary is not None and summary != total:
        lines.append(f"[FAIL] the report lists {total} skipped tests on SKIPPED lines but "
                     f"pytest's summary says {summary}; the report is truncated or not from -rs")
        return 1, lines
    if not skips:
        lines.append("[OK] no skipped tests in this report")
        return 0, lines
    per_class: Counter[str] = Counter()
    per_entry: dict[Entry, list[Skip]] = defaultdict(list)
    unknown: list[Skip] = []
    for s in skips:
        e = match(s.reason, entries)
        if e is None:
            unknown.append(s)
        else:
            per_class[e.cls] += s.count
            per_entry[e].append(s)
    lines.append(f"[skip-reasons] {total} skipped tests, {len(skips)} SKIPPED lines, "
                 f"{len(per_entry)} listed reasons, {len(unknown)} unlisted")
    for e, hits in sorted(per_entry.items(), key=lambda kv: (-sum(h.count for h in kv[1]), kv[0].cls)):
        n = sum(h.count for h in hits)
        lines.append(f"  {e.cls:<20} {n:4d}  {e.pattern.pattern}")
    for cls, n in sorted(per_class.items(), key=lambda kv: -kv[1]):
        lines.append(f"  class {cls:<20} {n:4d}")
    if unknown:
        lines.append(f"[FAIL] {len(unknown)} skip reason(s) match no entry in {ALLOWLIST.relative_to(ROOT)}; "
                     "add an entry that names what the skip depends on, or make the test run:")
        for s in unknown:
            lines.append(f"  {s.where}: {s.reason}")
        return 1, lines
    lines.append("[OK] every skipped test names a listed reason")
    return 0, lines


def main(argv: list[str]) -> int:
    args = argv[1:]
    if len(args) != 1:
        print("usage: check_skip_reasons.py <pytest-report-file|->", file=sys.stderr)
        return 2
    text = sys.stdin.read() if args[0] == "-" else Path(args[0]).read_text(encoding="utf-8", errors="replace")
    _, entries = load_allowlist()
    code, lines = check(text, entries)
    print("\n".join(lines), file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
