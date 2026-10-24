#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Select the test files a change can affect, for the pull-request CI leg.

The deterministic suite takes 14 to 20 minutes per interpreter. A pull
request runs the files this script selects; a push to master runs the whole
suite on every interpreter, so nothing merges on a subset alone. The
selection is conservative: when a change touches something whose reach is
not modelled here, the answer is ALL and the pull request runs everything.

Rules, in order of precedence:

1. **ALL** when any changed path is one the whole suite depends on or one the
   model does not cover: packaging and dependency files, pytest configuration,
   the test helpers that every test may load (``conftest.py``), the CI
   workflows, package ``__init__`` files, and any directory outside the ones
   listed in ``MODELLED_PREFIXES`` (deploy, integrations, frontend, workers,
   paper, provenance and the rest are read by tests in ways no import graph
   sees).
2. A changed Python module under ``remora/``, ``servers/``, ``scripts/`` or
   ``tests/`` selects every test file that imports it, transitively, through
   the repository's static import graph.
3. Any changed path selects every test file whose text names it: the
   repository-relative path, its basename, or its dotted module name. This
   catches tests that read data files, run scripts in a subprocess or import a
   module through a string (``REMORA_TOOL_REGISTRY_MODULE``).
4. A changed test file selects itself.
5. A changed document, register, artifact or schema (``docs/``,
   ``artifacts/``, ``schemas/`` and the top-level Markdown files) selects every
   docgate test file as well, since those assert on repository documents.
6. The docgate files are always included: they are fast and they are the
   gates on the registers every change may touch. An empty selection never
   happens; the smallest answer is the docgate set.

The output is one test file path per line, or the single line ``ALL``. The
``--report`` JSON says which rule selected each file, so a reviewer can see
why a test ran or did not.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Changed paths under these prefixes are modelled by rules 2 to 5. Anything
#: else is ALL (rule 1).
MODELLED_PREFIXES = ("remora/", "servers/", "scripts/", "tests/", "docs/", "artifacts/",
                     "schemas/")
#: Top-level files the model covers as documents (rule 5).
MODELLED_ROOT_FILES = frozenset({"README.md", "CHANGELOG.md", "NEGATIVE_RESULTS.md",
                                 "ARCHITECTURE.md", "DEVELOPER_OVERVIEW.md", "CONTRIBUTING.md",
                                 "CLAUDE.md", "LICENSE", "LICENSE-COMMERCIAL.md"})
#: Paths whose change means the whole suite runs (rule 1).
ALL_PATTERNS = (
    re.compile(r"^pyproject\.toml$"), re.compile(r"^requirements.*\.txt$"),
    re.compile(r"^setup\.(py|cfg)$"), re.compile(r"^Makefile$"),
    re.compile(r"(^|/)conftest\.py$"), re.compile(r"^pytest\.ini$"), re.compile(r"^tox\.ini$"),
    re.compile(r"^\.github/workflows/"), re.compile(r"^(remora|servers|scripts|tests)/__init__\.py$"),
    re.compile(r"^remora/[^/]+/__init__\.py$"), re.compile(r"^tests/data/"),
)
PACKAGES = ("remora", "servers", "scripts", "tests")
DOCGATE_MARK = re.compile(r"pytest\.mark\.docgate")


def changed_paths(base: str, head: str, cwd: Path = ROOT) -> list[str]:
    out = subprocess.run(["git", "diff", "--name-only", f"{base}...{head}"], cwd=cwd,
                         capture_output=True, text=True, check=True).stdout
    return sorted(p for p in out.splitlines() if p.strip())


def test_files(root: Path = ROOT) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in (root / "tests").rglob("test_*.py"))


def docgate_files(root: Path = ROOT) -> list[str]:
    out = []
    for rel in test_files(root):
        if DOCGATE_MARK.search((root / rel).read_text(encoding="utf-8", errors="replace")):
            out.append(rel)
    return out


def module_name(rel: str) -> str | None:
    """``remora/a/b.py`` -> ``remora.a.b``; ``remora/a/__init__.py`` -> ``remora.a``."""
    if not rel.endswith(".py") or not rel.startswith(tuple(p + "/" for p in PACKAGES)):
        return None
    parts = rel[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _imports(tree: ast.AST, known: set[str]) -> set[str]:
    """Static imports, plus every string literal that names a known module.

    A string is how the repository loads modules late: the execution router
    joins the app through a lazily imported name, the tool registry through
    ``REMORA_TOOL_REGISTRY_MODULE``, evidence and observer modules through
    their own settings. Treating such a literal as an import edge is what
    makes "tests of the app" depend on the execution API.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value.strip()
            if value in known or value.split(":")[0] in known:
                names.add(value.split(":")[0])
    return names


def import_graph(root: Path = ROOT) -> dict[str, set[str]]:
    """``{module: {modules that import it}}`` over the four packages."""
    modules: dict[str, str] = {}
    for pkg in PACKAGES:
        for path in (root / pkg).rglob("*.py"):
            rel = path.relative_to(root).as_posix()
            name = module_name(rel)
            if name:
                modules[name] = rel
    reverse: dict[str, set[str]] = defaultdict(set)
    for name, rel in modules.items():
        try:
            tree = ast.parse((root / rel).read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for imported in _imports(tree, set(modules)):
            # ``from a.b import c`` names a.b.c, which may be a module or an
            # attribute; both the module and its parent are dependencies.
            candidate = imported
            while candidate:
                if candidate in modules and candidate != name:
                    reverse[candidate].add(name)
                    break
                candidate = candidate.rpartition(".")[0]
    return reverse


def dependents(changed_modules: set[str], reverse: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set(changed_modules)
    queue = deque(changed_modules)
    while queue:
        for importer in reverse.get(queue.popleft(), ()):
            if importer not in seen:
                seen.add(importer)
                queue.append(importer)
    return seen


def select(changed: list[str], root: Path = ROOT) -> tuple[list[str] | None, dict[str, list[str]]]:
    """``(files, reasons)``; ``files`` is None for ALL."""
    reasons: dict[str, list[str]] = defaultdict(list)
    for path in changed:
        if any(rx.search(path) for rx in ALL_PATTERNS):
            return None, {"ALL": [f"{path}: the whole suite depends on it"]}
        if not path.startswith(MODELLED_PREFIXES) and path not in MODELLED_ROOT_FILES:
            return None, {"ALL": [f"{path}: outside the modelled prefixes"]}
    all_tests = test_files(root)
    reverse = import_graph(root)
    changed_modules = {m for m in (module_name(p) for p in changed) if m}
    affected = dependents(changed_modules, reverse) if changed_modules else set()
    for rel in all_tests:
        name = module_name(rel)
        if name and name in affected:
            reasons[rel].append("imports a changed module" if name not in changed_modules
                                else "changed test file")
    texts = {rel: (root / rel).read_text(encoding="utf-8", errors="replace") for rel in all_tests}
    for path in changed:
        tokens = {path, Path(path).name}
        dotted = module_name(path)
        if dotted:
            tokens.add(dotted)
        for rel, text in texts.items():
            if rel == path:
                continue
            if any(tok in text for tok in tokens):
                reasons[rel].append(f"names {path}")
    doc_change = any(p.startswith(("docs/", "artifacts/", "schemas/")) or p in MODELLED_ROOT_FILES
                     for p in changed)
    for rel in docgate_files(root):
        reasons[rel].append("docgate, documents changed" if doc_change else "docgate, always")
    return sorted(reasons), dict(reasons)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", required=True, help="the base commit (merge base is computed)")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--out", required=True, help="one test file per line, or ALL")
    parser.add_argument("--report", help="JSON with the reason each file was selected")
    args = parser.parse_args(argv)
    changed = changed_paths(args.base, args.head)
    files, reasons = select(changed)
    total = len(test_files())
    Path(args.out).write_text(("ALL\n" if files is None else "".join(f"{f}\n" for f in files)),
                              encoding="utf-8")
    if args.report:
        Path(args.report).write_text(json.dumps({
            "base": args.base, "head": args.head, "changed": changed,
            "selection": "ALL" if files is None else files, "test_files_total": total,
            "reasons": reasons}, indent=2), encoding="utf-8")
    if files is None:
        print(f"[ALL] {len(changed)} changed path(s); {reasons['ALL'][0]}")
    else:
        print(f"[SUBSET] {len(files)} of {total} test files selected for {len(changed)} changed path(s)")
        for f in files:
            print(f"  {f}: {'; '.join(reasons[f])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
