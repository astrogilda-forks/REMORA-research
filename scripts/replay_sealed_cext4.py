#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Replay the sealed C-ext4 track at a given commit and compare every count.

C-ext4 (SAP v6, CLAIM-021) was evaluated once, and ``run_bfcl_cext4.py``
refuses to run it again: a second run is not blind. The routing is
deterministic, though, so an outside reader can still ask a narrower question
that needs no blindness: does the committed code at the locked commit,
applied to the committed episodes, produce exactly the counts the result file
publishes? This script answers it. A replay is a reproducibility check, not
a new result, and it never writes to the manifest or the result file.

By default it checks out the manifest's ``locked_at_commit`` into a temporary
git worktree (needs full history), verifies that the frozen code and data
there match the hashes recorded at seal time, routes every arm, and compares
each arm's n and d for every metric with ``per_arm_metrics`` in
``results/routing_bench_bfcl_v4_cext4_results.json``.

``--at working-tree`` replays the current tree instead, without hash checks
on the frozen code. It shows whether today's code still produces the
published counts; a difference there is drift to record, not a failure of
the sealed result, which binds to the locked commit.

    python scripts/replay_sealed_cext4.py
    python scripts/replay_sealed_cext4.py --at working-tree
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_REL = Path("data") / "routing_bench_bfcl_v4_cext4"
RESULT = REPO_ROOT / "results" / "routing_bench_bfcl_v4_cext4_results.json"
WORKING_TREE = "working-tree"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def frozen_mismatches(root: Path, manifest: dict) -> list[str]:
    """Frozen code and data under *root* that differ from the seal-time hashes."""
    # Load the builder from *root* under a private name, so its FROZEN_FILES
    # resolve inside *root* even if another tree's copy is already imported.
    spec = importlib.util.spec_from_file_location(
        "_cext4_builder_replay", root / "scripts" / "build_bfcl_v4_cext4.py")
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    frozen: dict[str, Path] = builder.FROZEN_FILES
    bad = [key for key, path in frozen.items()
           if _sha(path) != manifest["frozen_sha256"].get(key)]
    if set(frozen) != set(manifest["frozen_sha256"]):
        bad.append("frozen file set")
    data = root / DATA_REL
    for name, key in (("bfcl_holdout.jsonl", "sha256"), ("registry.json", "registry_sha256"),
                      ("descriptions.json", "descriptions_sha256")):
        if _sha(data / name) != manifest[key]:
            bad.append(name)
    return bad


def route_counts(root: Path) -> dict[str, dict[str, list[int]]]:
    """Route every arm with the code under *root*; return n and d per metric.

    Runs in a child process so the ``remora`` package is imported from *root*,
    not from wherever the parent process found it.
    """
    child = (
        "import json, sys\n"
        f"root = {str(root)!r}\n"
        "sys.path.insert(0, root)\n"
        "import remora\n"
        "from pathlib import Path\n"
        "assert Path(remora.__file__).resolve().is_relative_to(Path(root).resolve()), "
        "remora.__file__\n"
        "from remora.toolcall.routing.bfcl_arms import ARMS, metrics, route_arm\n"
        "from remora.toolcall.routing.episode import RoutingEpisode\n"
        "from remora.toolcall.routing.tool_registry import ToolRegistry\n"
        f"d = Path(root) / {str(DATA_REL.as_posix())!r}\n"
        "eps = [RoutingEpisode.from_json_dict(json.loads(l)) for l in "
        "(d / 'bfcl_holdout.jsonl').read_text(encoding='utf-8').splitlines() if l.strip()]\n"
        "reg = ToolRegistry.from_json_dict(json.loads((d / 'registry.json')"
        ".read_text(encoding='utf-8')))\n"
        "desc = json.loads((d / 'descriptions.json').read_text(encoding='utf-8'))\n"
        "out = {a: {k: [m['n'], m['d']] for k, m in "
        "metrics(route_arm(a, eps, reg, desc), eps).items()} for a in ARMS}\n"
        "print(json.dumps(out, sort_keys=True))\n"
    )
    proc = subprocess.run([sys.executable, "-c", child], cwd=root, capture_output=True,
                          text=True, encoding="utf-8", check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"replay failed:\n{proc.stderr}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


def compare(replayed: dict[str, dict[str, list[int]]], published: dict) -> list[str]:
    """Every arm and metric whose n or d differs from the published file."""
    diffs = []
    for arm in sorted(set(replayed) | set(published)):
        if arm not in replayed or arm not in published:
            diffs.append(f"{arm}: arm present on one side only")
            continue
        for name in sorted(set(replayed[arm]) | set(published[arm])):
            got = replayed[arm].get(name)
            want = published[arm].get(name)
            want_nd = [want["n"], want["d"]] if want else None
            if got != want_nd:
                diffs.append(f"{arm}.{name}: published {want_nd}, replayed {got}")
    return diffs


def _worktree(commit: str, into: Path) -> None:
    subprocess.run(["git", "-C", str(REPO_ROOT), "worktree", "add", "--detach", "-q",
                    str(into), commit], check=True)


def _remove_worktree(path: Path) -> None:
    subprocess.run(["git", "-C", str(REPO_ROOT), "worktree", "remove", "--force", str(path)],
                   check=False, capture_output=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--at", default=None,
                        help="commit to replay (default: the manifest's locked_at_commit), "
                             f"or '{WORKING_TREE}'")
    args = parser.parse_args(argv)

    manifest = json.loads((REPO_ROOT / DATA_REL / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("status") != "evaluated":
        print("REFUSING: C-ext4 is not evaluated; a replay now would unseal it.",
              file=sys.stderr)
        return 2
    published = json.loads(RESULT.read_text(encoding="utf-8"))["per_arm_metrics"]
    at = args.at or manifest["locked_at_commit"]

    if at == WORKING_TREE:
        print(f"replaying C-ext4 on the working tree ({REPO_ROOT})")
        replayed = route_counts(REPO_ROOT)
    else:
        tmp = Path(tempfile.mkdtemp(prefix="cext4-replay-"))
        tree = tmp / "tree"
        try:
            _worktree(at, tree)
            bad = frozen_mismatches(tree, manifest)
            if bad:
                print(f"FAIL: at {at} the frozen inputs differ from the seal: {bad}")
                return 1
            print(f"replaying C-ext4 at {at}: frozen code and data match the seal")
            replayed = route_counts(tree)
        finally:
            _remove_worktree(tree)

    diffs = compare(replayed, published)
    checked = sum(len(m) for m in replayed.values())
    if diffs:
        print(f"FAIL: {len(diffs)} of {checked} arm-metric counts differ:")
        for d in diffs:
            print(f"  {d}")
        return 1
    print(f"PASS: all {checked} arm-metric counts (n and d, {len(replayed)} arms) "
          "equal the published result")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
