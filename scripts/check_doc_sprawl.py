#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Report documentation that may be sprawl: candidates for deletion or merging.

Report only. It never deletes, moves or edits a file; what to do with a
candidate is a judgement the remora-desprawl skill describes. A document is
a candidate when it is NOT protected and shows at least one sprawl signal:

  orphan        nothing outside the registers links to it or names its path
  stale         the document register says verdict=stale
  unaudited     the register has never recorded a review (last_reviewed null)
  placeholder   generic template text or fabricated example results
  near_dup      most of its prose shingles also occur in another document
  superseded_by a later version of the same document exists (name_v1 / _v2)
  stub          fewer than 12 prose lines
  archive_twin  an archived copy with no prose line of its own: every line is in
                a live document, so the archive keeps nothing the live file and
                git history do not

Protected, never a candidate, because the repository's rules keep them
verbatim or because evidence points at them:

  - pre-registered and frozen documents (statistical analysis plans,
    PREREGISTERED.md, superseded_claims.md), NEGATIVE_RESULTS.md, the paper,
    CHANGELOG, licences, agent instruction files;
  - register status historical or generated, and docs/archive/, except an
    archive_twin, which preserves nothing;
  - anything a claim, capability, test, script, workflow or Python module
    names by path.

    python scripts/check_doc_sprawl.py            # table, most signals first
    python scripts/check_doc_sprawl.py --json     # machine-readable

Exit code is always 0 unless the repository cannot be read: the output is a
worklist, not a gate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "docs" / "assurance" / "document_register_v1.yaml"

DOC_SUFFIXES = (".md",)
#: Documents the repository keeps verbatim by policy, by path prefix or name.
PROTECTED_PREFIXES = (
    "docs/archive/", "attic/", "docs/researchpapers/", "paper/",
    "artifacts/", "results/", "data/", "datasets/", "tests/", "legal/",
    "LICENSES/", ".github/", ".claude/", ".agents/", "experiments/",
    "integrations/", "conformance/", "node_modules/", "frontend/node_modules/",
)
PROTECTED_NAMES = {
    "NEGATIVE_RESULTS.md", "CHANGELOG.md", "README.md", "CLAUDE.md", "AGENTS.md",
    "LICENSE.md", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
    "PREREGISTERED.md", "superseded_claims.md",
}
PROTECTED_PATTERNS = (
    re.compile(r"statistical_analysis_plan"),
    re.compile(r"preregist", re.I),
    re.compile(r"pre-registered", re.I),
)
#: Files whose mention of a path is bookkeeping, not use.
REGISTER_FILES = {
    "docs/assurance/document_register_v1.yaml",
    "docs/assurance/prose_style_baseline.json",
    "docs/README.md",
}
#: Files whose mention of a path means evidence depends on the document.
EVIDENCE_GLOBS = ("*.py", "*.yml", "*.yaml", "*.json", "*.toml", "*.ts", "*.tex")

PLACEHOLDER = re.compile(
    r"lorem ipsum|\[your [a-z ]+\]|our method achieves|state-of-the-art performance"
    r"|todo: fill|insert (figure|table|results) here|\bxx\.x\b|placeholder text",
    re.I,
)
ARCHIVE_NOTICE = re.compile(r"\bNOTICE\b.*\b(HISTORICAL|archived)\b", re.I)
VERSION = re.compile(r"^(?P<stem>.+?)[_-]v(?P<n>\d+)(?:\.\d+)*$")
STUB_LINES = 12
SHINGLE = 8
NEAR_DUP = 0.5
#: An archived copy counts as a twin when this share of its shingles is live.
TWIN = 0.9


def tracked(pattern: str) -> list[str]:
    out = subprocess.run(["git", "ls-files", pattern], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout
    return [p for p in out.splitlines() if p]


def is_protected(path: str, status: str | None, text: str) -> str | None:
    name = Path(path).name
    if path.startswith(PROTECTED_PREFIXES):
        return "frozen or third-party location"
    if name in PROTECTED_NAMES:
        return "kept by policy"
    if any(rx.search(path) for rx in PROTECTED_PATTERNS):
        return "pre-registered or frozen"
    if status in ("historical", "generated"):
        return f"register status {status}"
    head = text[:600].lower()
    if "pre-registered" in head or "preregistered" in head or "frozen" in head.split("\n", 3)[0]:
        return "declares itself pre-registered or frozen"
    return None


def prose(text: str) -> list[str]:
    lines, fence = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        s = line.strip()
        if fence or not s or s.startswith(("#", "|", "<", "---")):
            continue
        if ARCHIVE_NOTICE.search(s):
            continue  # the banner an archived copy gains is not content
        lines.append(s)
    return lines


def shingles(lines: list[str]) -> set[tuple[str, ...]]:
    words = re.findall(r"[a-z0-9]+", " ".join(lines).lower())
    return {tuple(words[i:i + SHINGLE]) for i in range(max(0, len(words) - SHINGLE + 1))}


def references(paths: list[str]) -> tuple[dict[str, int], dict[str, list[str]]]:
    """Inbound mentions per document: from docs, and from evidence files."""
    corpus = {p: (ROOT / p).read_text(encoding="utf-8", errors="replace")
              for p in tracked("*.md") + [f for g in EVIDENCE_GLOBS for f in tracked(g)]
              if (ROOT / p).is_file() and p not in REGISTER_FILES}
    inbound: dict[str, int] = defaultdict(int)
    evidence: dict[str, list[str]] = defaultdict(list)
    for doc in paths:
        # The path, or the path relative to docs/ as links write it. A bare file
        # name is not enough: an archived copy shares it with the live file.
        keys = {doc}
        if doc.startswith("docs/"):
            keys.add(doc[len("docs/"):])
        stem = Path(doc).stem
        if len(stem) >= 15 and not doc.startswith("docs/archive/"):
            # Registers cite a distinctive document by name alone
            # ("ADR-tainted-argument-floor-order"); an archived copy shares the
            # name with the live file, so only live documents get this key.
            keys.add(stem)
        for src, text in corpus.items():
            if src == doc:
                continue
            hit = any(k in text for k in keys)
            if not hit and src.endswith(".md"):
                # A Markdown link is relative to the file that holds it, so a
                # sibling links "FINDINGS.md". Matched as a link target only.
                rel = os.path.relpath(doc, os.path.dirname(src) or ".")
                hit = re.search(r"\]\(\s*(?:\./)?" + re.escape(rel) + r"\s*[#)]", text) is not None
            if not hit:
                continue
            if src.endswith(".md"):
                inbound[doc] += 1
            else:
                evidence[doc].append(src)
    return inbound, evidence


def scan() -> list[dict]:
    register = yaml.safe_load(REGISTER.read_text(encoding="utf-8"))
    entries = {d["path"]: d for d in register.get("documents", [])}
    docs = [p for p in tracked("*.md") if not p.startswith(("node_modules/", "frontend/node_modules/"))]
    texts = {p: (ROOT / p).read_text(encoding="utf-8", errors="replace") for p in docs}
    inbound, evidence = references(docs)
    index_path = ROOT / "docs" / "README.md"
    index = index_path.read_text(encoding="utf-8") if index_path.is_file() else ""
    stems: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for p in docs:
        m = VERSION.match(str(Path(p).with_suffix("")))
        if m:
            stems[m["stem"]].append((int(m["n"]), p))
    shingle_sets = {p: shingles(prose(texts[p])) for p in docs}
    rows = []
    for p in docs:
        entry = entries.get(p, {})
        status = entry.get("status")
        reason = is_protected(p, status, texts[p])
        if reason is None and evidence.get(p):
            reason = "named by " + ", ".join(sorted(evidence[p])[:3])
        signals = []
        if inbound.get(p, 0) == 0 and not evidence.get(p):
            signals.append("orphan")
        if entry.get("verdict") == "stale":
            signals.append("stale")
        if entry and entry.get("last_reviewed") in (None, "") and entry.get("last_audited") in (None, ""):
            signals.append("unaudited")
        if PLACEHOLDER.search(texts[p]):
            signals.append("placeholder")
        if len(prose(texts[p])) < STUB_LINES:
            signals.append("stub")
        m = VERSION.match(str(Path(p).with_suffix("")))
        if m:
            later = [q for n, q in stems[m["stem"]] if n > int(m["n"])]
            if later:
                signals.append("superseded_by:" + sorted(later)[-1])
        mine = shingle_sets[p]
        archived = p.startswith("docs/archive/")
        # Short archived files can still be exact copies; live near-duplicates
        # need enough text for the share to mean something.
        if len(mine) >= (5 if archived else 40):
            for q, theirs in shingle_sets.items():
                if q == p or not theirs:
                    continue
                share = len(mine & theirs) / len(mine)
                if archived and not q.startswith("docs/archive/") and share >= TWIN:
                    # A twin keeps nothing: every prose line it holds is in the
                    # live file. A copy with even one line of its own may hold a
                    # superseded finding, which the repository keeps.
                    live_lines = set(prose(texts[q]))
                    own = [x for x in prose(texts[p]) if x not in live_lines]
                    if not own:
                        signals.append("archive_twin:" + q)
                        break
                # A live document that matches an archived copy is the original,
                # not the duplicate; the copy is reported as the twin.
                if not archived and not q.startswith("docs/archive/") and share >= NEAR_DUP:
                    signals.append("near_dup:" + q)
                    break
        if archived and any(s.startswith("archive_twin:") for s in signals) and not evidence.get(p):
            reason = None
            signals = [s for s in signals if s.startswith("archive_twin:")]
        rows.append({"path": p, "protected": reason, "signals": signals,
                     "inbound_doc_links": inbound.get(p, 0), "register": status or "unregistered",
                     "indexed": p.startswith("docs/") and p[len("docs/"):] in index,
                     "lines": texts[p].count("\n")})
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--all", action="store_true", help="include protected documents")
    args = parser.parse_args(argv)
    rows = scan()
    candidates = [r for r in rows if r["signals"] and not r["protected"]]
    candidates.sort(key=lambda r: (-len(r["signals"]), r["inbound_doc_links"], r["path"]))
    if args.json:
        print(json.dumps({"documents": len(rows), "candidates": candidates,
                          "protected": [r for r in rows if r["protected"]] if args.all else None},
                         indent=2))
        return 0
    print(f"{len(rows)} Markdown documents; {len(candidates)} unprotected with a sprawl signal\n")
    for r in candidates:
        print(f"{len(r['signals'])}  {r['path']}  [{r['register']}, {'indexed, ' if r['indexed'] else ''}"
              f"{r['inbound_doc_links']} doc links, "
              f"{r['lines']} lines]  {' '.join(r['signals'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
