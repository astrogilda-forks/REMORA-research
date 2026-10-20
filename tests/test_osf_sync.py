"""scripts/osf_sync.py: layout coverage, plan contents and sync/verify against an in-memory OSF."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("osf_sync", ROOT / "scripts" / "osf_sync.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["osf_sync"] = module
    spec.loader.exec_module(module)
    return module


osf = _load()


class FakeOSF:
    """Folders and files keyed by relative path; OSF paths are opaque ids."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, bytes]] = {}
        self.dirs: dict[str, set[str]] = {}
        self.wikis: dict[str, str] = {}
        self.ops: list[tuple[str, str, str]] = []

    def _files(self, node: str) -> dict[str, bytes]:
        return self.nodes.setdefault(node, {})

    def tree(self, node: str):
        files = {rel: (hashlib.sha256(data).hexdigest(), f"/f:{rel}")
                 for rel, data in self._files(node).items()}
        folders = {"": "/"} | {rel: f"/d:{rel}/" for rel in self.dirs.get(node, set())}
        return osf.RemoteTree(files, folders)

    def mkdir(self, node: str, parent: str, name: str) -> str:
        base = "" if parent == "/" else parent[3:-1]
        rel = f"{base}/{name}" if base else name
        self.dirs.setdefault(node, set()).add(rel)
        self.ops.append(("mkdir", node, rel))
        return f"/d:{rel}/"

    def create(self, node: str, parent: str, name: str, data: bytes) -> None:
        base = "" if parent == "/" else parent[3:-1]
        rel = f"{base}/{name}" if base else name
        assert rel not in self._files(node)
        self._files(node)[rel] = data
        self.ops.append(("create", node, rel))

    def update(self, node: str, path: str, data: bytes) -> None:
        self._files(node)[path[3:]] = data
        self.ops.append(("update", node, path[3:]))

    def delete(self, node: str, path: str) -> None:
        if path.startswith("/d:"):
            rel = path[3:-1]
            self.dirs[node].discard(rel)
            for f in [f for f in self._files(node) if f.startswith(rel + "/")]:
                del self._files(node)[f]
        else:
            rel = path[3:]
            del self._files(node)[rel]
        self.ops.append(("delete", node, rel))

    def wiki(self, node: str) -> str | None:
        return self.wikis.get(node)

    def set_wiki(self, node: str, text: str) -> None:
        self.wikis[node] = text
        self.ops.append(("wiki", node, ""))


def _snapshot(files: dict[str, bytes]):
    base = {"LICENSE": b"BUSL", "CITATION.cff": b"cff", "README.md": b"# r"}
    return osf.Snapshot("a" * 40, "2026-10-20T00:00:00+02:00", base | files)


def _plan(plans, key: str):
    node = next(c.node for c in osf.LAYOUT if c.key == key)
    return next(p for p in plans if p.node == node)


def test_every_tracked_file_has_exactly_one_component() -> None:
    assert osf.main(["check"]) == 0


def test_component_nodes_are_distinct_and_not_the_project() -> None:
    nodes = [c.node for c in osf.LAYOUT]
    assert len(set(nodes)) == len(nodes) == 6
    assert osf.OSF_PROJECT not in nodes


def test_unassigned_and_doubly_assigned_paths_are_refused() -> None:
    with pytest.raises(osf.LayoutError, match="newdir/x.py: no component"):
        osf.assign(["remora/a.py", "newdir/x.py"])
    with pytest.raises(osf.LayoutError, match="stray.txt: no component"):
        osf.assign(["stray.txt"])


def test_plan_manifest_lists_every_component_file_with_its_hash() -> None:
    plans = osf.build_plans(_snapshot({"remora/a.py": b"x = 1\n", "tests/t.py": b"t"}))
    software = _plan(plans, "software")
    manifest = software.files["MANIFEST.sha256"].decode().splitlines()
    assert manifest == [f"{hashlib.sha256(b'x = 1' + bytes([10])).hexdigest()}  remora/a.py"]
    meta = json.loads(software.files["SNAPSHOT.json"])
    assert meta["commit"] == "a" * 40 and meta["files"] == 1
    assert "not open source" in meta["license"]
    assert software.wiki == software.files["README.md"].decode()


def test_root_plan_carries_overview_licence_and_citation() -> None:
    root = osf.build_plans(_snapshot({}))[0]
    assert root.node == osf.OSF_PROJECT
    assert set(root.files) == {"README.md", "LICENSE", "CITATION.cff"}
    readme = root.files["README.md"].decode()
    for c in osf.LAYOUT:
        assert f"https://osf.io/{c.node}/" in readme
    assert "not preregistrations" in readme


def test_sync_from_empty_then_verify_is_clean() -> None:
    store = FakeOSF()
    plans = osf.build_plans(_snapshot({"remora/sub/a.py": b"a", "docs/x.md": b"x"}))
    for plan in plans:
        osf.sync_plan(store, plan, workers=1)
    assert osf.verify_plans(store, plans) == []
    assert store.nodes[_plan(plans, "software").node]["remora/sub/a.py"] == b"a"


def test_generated_files_are_written_after_content() -> None:
    store = FakeOSF()
    plan = _plan(osf.build_plans(_snapshot({"remora/a.py": b"a", "remora/b.py": b"b"})), "software")
    osf.sync_plan(store, plan, workers=1)
    writes = [rel for op, _, rel in store.ops if op in ("create", "update")]
    first_generated = min(writes.index(g) for g in osf.GENERATED)
    assert all(writes.index(r) < first_generated for r in ("remora/a.py", "remora/b.py"))


def test_resync_uploads_only_changes_and_removes_untracked_files() -> None:
    store = FakeOSF()
    old = osf.build_plans(_snapshot({"remora/a.py": b"a", "remora/gone/b.py": b"b",
                                     "remora/same.py": b"s"}))
    for plan in old:
        osf.sync_plan(store, plan, workers=1)
    store.ops.clear()
    new = osf.build_plans(_snapshot({"remora/a.py": b"A", "remora/same.py": b"s",
                                     "remora/c.py": b"c"}))
    drift = osf.sync_plan(store, _plan(new, "software"), workers=1)
    assert drift.missing == ["remora/c.py"]
    assert "remora/a.py" in drift.changed and "remora/same.py" not in drift.changed
    assert drift.extra == ["remora/gone/b.py"]
    touched = {rel for op, _, rel in store.ops if op != "wiki"}
    assert "remora/same.py" not in touched
    assert ("delete", _plan(new, "software").node, "remora/gone") in store.ops
    assert osf.verify_plans(store, [_plan(new, "software")]) == []


def test_unchanged_resync_writes_nothing() -> None:
    store = FakeOSF()
    plans = osf.build_plans(_snapshot({"remora/a.py": b"a"}))
    for plan in plans:
        osf.sync_plan(store, plan, workers=1)
    store.ops.clear()
    for plan in plans:
        osf.sync_plan(store, plan, workers=1)
    assert store.ops == []


def test_verify_reports_missing_changed_and_extra() -> None:
    store = FakeOSF()
    plan = _plan(osf.build_plans(_snapshot({"remora/a.py": b"a", "remora/b.py": b"b"})), "software")
    osf.sync_plan(store, plan, workers=1)
    files = store.nodes[plan.node]
    del files["remora/a.py"]
    files["remora/b.py"] = b"tampered"
    files["remora/planted.py"] = b"p"
    problems = osf.verify_plans(store, [plan])
    assert any("missing remora/a.py" in p for p in problems)
    assert any("changed remora/b.py" in p for p in problems)
    assert any("extra remora/planted.py" in p for p in problems)


def test_remote_modes_refuse_to_run_without_a_token(monkeypatch) -> None:
    monkeypatch.delenv("OSF_TOKEN", raising=False)
    assert osf.main(["verify"]) == 2


PAPER = """# Title

## Abstract

First paragraph.

<!-- claim:CLAIM-001 far_pct n -->
**Result.** Second paragraph.

**Keywords:** a, b

## 1. Introduction

Body.
"""

REGISTER = """claims:
  - id: CLAIM-002
    title: "Superseded thing"
    status: superseded
    evidence_level: internal_benchmark
  - id: CLAIM-001
    title: "Active | piped"
    status: active
    evidence_level: externally_benchmarked
    blindness: blind
"""


def test_abstract_drops_claim_anchors_keywords_and_later_sections() -> None:
    text = osf.abstract(_snapshot({"paper/remora_paper.md": PAPER.encode()}))
    assert text.startswith("First paragraph.") and "**Result.** Second paragraph." in text
    assert "<!--" not in text and "Keywords" not in text and "Body." not in text


def test_claims_table_comes_from_the_register_active_first() -> None:
    table = osf.claims_table(_snapshot({osf.CLAIM_REGISTER: REGISTER.encode()}))
    assert table.startswith("2 claims, 1 active.")
    rows = [ln for ln in table.splitlines() if ln.startswith("| CLAIM-")]
    assert rows[0].startswith(r"| CLAIM-001 | Active \| piped | active | externally_benchmarked | blind |")
    assert rows[1].endswith("| superseded | internal_benchmark | not stated |")


def test_datasets_table_reads_status_size_and_upstream_licence() -> None:
    manifest = {"status": "evaluated", "n_episodes": 12,
                "upstream": {"repo": "https://github.com/ShishirPatil/gorilla", "license": "Apache-2.0"}}
    table = osf.datasets_table(_snapshot({"data/track/manifest.json": json.dumps(manifest).encode()}))
    assert "| `data/track/` | evaluated | 12 | gorilla (Apache-2.0) |" in table


def test_strict_build_refuses_a_research_map_entry_that_is_not_tracked() -> None:
    snap = _snapshot({})
    assert "docs/06-reproducibility.md" in osf.missing_research_paths(snap)
    with pytest.raises(osf.LayoutError, match="RESEARCH_MAP"):
        osf.build_plans(snap, strict=True)


def test_root_page_states_rights_participants_and_corrections() -> None:
    readme = osf.build_plans(_snapshot({}))[0].wiki
    for heading in ("## Rights, data and corrections", "**Human participants.**", "**Corrections.**"):
        assert heading in readme


class _Response:
    def __init__(self, status: int, body: dict | None = None) -> None:
        self.status_code, self._body, self.headers, self.text = status, body or {}, {}, ""

    def json(self) -> dict:
        return self._body


class _Session:
    def __init__(self, responses: list[_Response]) -> None:
        self.responses, self.calls, self.headers = responses, [], {}

    def request(self, method: str, url: str, **kw) -> _Response:
        self.calls.append((method, url))
        return self.responses.pop(0)


def _client(responses: list[_Response]):
    client = osf.OSF.__new__(osf.OSF)
    client.session = _Session(responses)
    return client


def test_create_that_meets_its_own_lost_first_attempt_updates_the_existing_file(monkeypatch) -> None:
    monkeypatch.setattr(osf.time, "sleep", lambda s: None)
    conflict = _Response(409, {"data": {"id": "osfstorage/abc123", "type": "files"}})
    client = _client([_Response(503), conflict, _Response(200)])
    client.create("node", "/dir/", "a.py", b"a")
    method, url = client.session.calls[-1]
    assert method == "PUT" and url.endswith("/providers/osfstorage/abc123?kind=file")


def test_mkdir_conflict_returns_the_existing_folder_path() -> None:
    client = _client([_Response(409, {"data": {"id": "osfstorage/f00/", "type": "files"}})])
    assert client.mkdir("node", "/", "docs") == "/f00/"
