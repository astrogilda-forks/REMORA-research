# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The sprawl detector proposes only what may go, and never what must stay."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_doc_sprawl.py"
BODY = "\n".join(f"Line {i} of a document about governed execution and its evidence." for i in range(20))


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("check_doc_sprawl", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    def write(rel: str, text: str) -> None:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    write("docs/assurance/document_register_v1.yaml",
          "documents:\n- {path: docs/old.md, status: canonical, verdict: stale}\n")
    write("docs/README.md", "[live](live.md)\n")
    write("docs/live.md", BODY)
    write("docs/linker.md", "See [live](live.md) and [cited](cited.md).\n" + BODY.replace("Line", "Row"))
    write("docs/cited.md", BODY.replace("Line", "Item"))
    write("docs/orphan.md", BODY.replace("Line", "Point"))
    write("docs/old.md", BODY.replace("Line", "Entry") + "\nSee live.md.\n")
    write("docs/template.md", "Our method achieves state-of-the-art performance.\n" + BODY.replace("Line", "Cell"))
    write("docs/archive/legacy/live.md", "> **NOTICE:** This document is **HISTORICAL** and archived.\n" + BODY)
    write("docs/archive/legacy/variant.md", BODY + "\nA superseded finding that only the archive keeps.\n")
    write("docs/statistical_analysis_plan_v9.md", BODY.replace("Line", "Plan"))
    write("NEGATIVE_RESULTS.md", BODY.replace("Line", "Result"))
    write("scripts/uses_cited.py", 'PATH = "docs/cited.md"\n')
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    monkeypatch.setattr(mod, "REGISTER", tmp_path / "docs/assurance/document_register_v1.yaml")
    return mod


def _rows(mod):
    return {r["path"]: r for r in mod.scan()}


def test_protected_documents_are_never_candidates(repo):
    rows = _rows(repo)
    for path in ("NEGATIVE_RESULTS.md", "docs/statistical_analysis_plan_v9.md",
                 "docs/archive/legacy/variant.md", "docs/cited.md"):
        assert rows[path]["protected"], path


def test_a_document_named_by_code_is_protected_as_evidence(repo):
    assert "scripts/uses_cited.py" in _rows(repo)["docs/cited.md"]["protected"]


def test_an_exact_archive_copy_is_a_twin_and_a_variant_is_not(repo):
    rows = _rows(repo)
    twin = rows["docs/archive/legacy/live.md"]
    assert twin["protected"] is None
    assert twin["signals"] == ["archive_twin:docs/live.md"]
    assert not any(s.startswith("archive_twin") for s in rows["docs/archive/legacy/variant.md"]["signals"])


def test_orphan_stale_and_placeholder_signals(repo):
    rows = _rows(repo)
    assert "orphan" in rows["docs/orphan.md"]["signals"]
    assert "stale" in rows["docs/old.md"]["signals"]
    assert "placeholder" in rows["docs/template.md"]["signals"]
    assert "orphan" not in rows["docs/live.md"]["signals"]


def test_a_bare_file_name_does_not_count_as_a_reference(repo):
    """docs/old.md says "live.md"; that must not protect or link the archive copy."""
    assert _rows(repo)["docs/archive/legacy/live.md"]["inbound_doc_links"] == 0


def test_the_report_never_writes(repo, capsys):
    before = {p: p.read_bytes() for p in repo.ROOT.rglob("*") if p.is_file() and ".git" not in p.parts}
    assert repo.main([]) == 0
    after = {p: p.read_bytes() for p in repo.ROOT.rglob("*") if p.is_file() and ".git" not in p.parts}
    assert before == after
    assert "unprotected with a sprawl signal" in capsys.readouterr().out


def test_a_sibling_link_counts_and_a_bare_mention_does_not(repo):
    review = repo.ROOT / "docs" / "reviews" / "r1"
    review.mkdir(parents=True)
    (review / "FINDINGS.md").write_text(BODY.replace("Line", "Finding"), encoding="utf-8")
    (review / "INDEX.md").write_text("See [findings](FINDINGS.md#top).\n" + BODY.replace("Line", "Index"),
                                     encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo.ROOT, check=True)
    rows = _rows(repo)
    assert rows["docs/reviews/r1/FINDINGS.md"]["inbound_doc_links"] == 1
    assert "orphan" not in rows["docs/reviews/r1/FINDINGS.md"]["signals"]
    assert rows["docs/archive/legacy/live.md"]["inbound_doc_links"] == 0


def test_a_register_citing_a_distinctive_name_protects_the_document(repo):
    adr = repo.ROOT / "docs" / "architecture" / "ADR-some-accepted-decision.md"
    adr.parent.mkdir(parents=True)
    adr.write_text(BODY.replace("Line", "Decision"), encoding="utf-8")
    (repo.ROOT / "docs" / "assurance" / "capability_register_v1.yaml").write_text(
        "caps: [{note: 're-audited for WP-1 (ADR-some-accepted-decision, accepted)'}]\n",
        encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo.ROOT, check=True)
    row = _rows(repo)["docs/architecture/ADR-some-accepted-decision.md"]
    assert "capability_register_v1.yaml" in row["protected"]
