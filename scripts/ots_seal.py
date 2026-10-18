#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""External timestamps for sealed files with OpenTimestamps (PRF-026).

A seal in this repository is a set of SHA-256 hashes in a committed manifest.
On its own that shows only the order in which the hashes entered a git
history the maintainer controls. This script binds the sealed files to the
Bitcoin blockchain through the public OpenTimestamps calendars, so a reader
can check that a file existed in its sealed form no later than a given block.

Only a 32-byte digest leaves the machine. `ots stamp` sends the SHA-256 of the
manifest (which lists the SHA-256 of each sealed file) to the calendars; no
file content is uploaded.

Group (scripts/README.md): demos and generators, run by hand. It does not
gate CI. The offline checks are tested in tests/test_ots_seal.py.

Which files are sealed is read from the seal records, not listed by hand:

- every tracked ``data/*/manifest.json`` that carries a ``status`` field
  (the seal state: ``sealed_never_run``, ``locked_never_run``, ``evaluated``);
- the ``manifest.provenance.json`` sidecar beside such a manifest, if any;
- every statistical analysis plan, ``docs/assurance/statistical_analysis_plan*.md``,
  and any further path named by a manifest's ``sap`` field.

Files the data manifests hash (episodes, frozen code, bundles) are covered
transitively: their digests are inside the stamped manifests.

A timestamp proves existence from the day it was made. A stamp made today
says nothing about the original sealing dates of SAP v5 or v6.

Subcommands::

    python scripts/ots_seal.py build  artifacts/timestamps/seal_manifest_<date>.json
    python scripts/ots_seal.py stamp  artifacts/timestamps/seal_manifest_<date>.json
    python scripts/ots_seal.py upgrade artifacts/timestamps/seal_manifest_<date>.json.ots
    python scripts/ots_seal.py info   artifacts/timestamps/seal_manifest_<date>.json.ots
    python scripts/ots_seal.py verify artifacts/timestamps/seal_manifest_<date>.json [--network]

``stamp`` builds the manifest and then runs ``ots stamp`` on it. ``verify``
is offline by default: it re-hashes every listed file, reports any that
changed, and checks that the proof commits to the manifest's digest.
``--network`` also runs ``ots verify``, which needs a Bitcoin node (or use
``ots --no-bitcoin verify`` and compare the reported block header by hand).

The client is the official ``opentimestamps-client``, tested with 0.7.2
(``pip install opentimestamps-client==0.7.2`` in a separate virtual
environment). It is not a project dependency, so the replication-pack lock
pin is unaffected. Set ``OTS_BIN`` or pass ``--ots-bin`` to point at it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "ots_seal_manifest_v1"
OTS_CLIENT_VERSION = "0.7.2"
SAP_GLOB = "docs/assurance/statistical_analysis_plan*.md"
DATA_MANIFEST_GLOB = "data/*/manifest.json"
SIDECAR_NAME = "manifest.provenance.json"
HASH_PROTOCOL = "sha256 over committed (LF) bytes; CRLF is normalised to LF before hashing"
SELECTION_RULE = (
    "data/*/manifest.json with a 'status' field, its manifest.provenance.json "
    "sidecar, docs/assurance/statistical_analysis_plan*.md, and every path in a "
    "manifest's 'sap' field"
)

# OpenTimestamps detached-proof header: magic, major version 1, then the file
# hash operation (0x08 = SHA-256) and the 32-byte digest it commits to.
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_OP_SHA256 = 0x08


def lf_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _tracked(root: Path, pattern: str) -> list[str] | None:
    """Tracked paths matching ``pattern``; None when root is not a git checkout."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "--", pattern], cwd=root,
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return [line for line in out.splitlines() if line]


def _matching(root: Path, pattern: str) -> list[str]:
    tracked = _tracked(root, pattern)
    if tracked is not None and (root / ".git").exists():
        return tracked
    return [p.relative_to(root).as_posix() for p in root.glob(pattern) if p.is_file()]


def select_sealed_files(root: Path = ROOT) -> dict[str, str]:
    """Map each sealed path (posix, relative to root) to its role."""
    roles: dict[str, str] = {}
    for rel in _matching(root, DATA_MANIFEST_GLOB):
        try:
            record = json.loads((root / rel).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict) or "status" not in record:
            continue
        roles[rel] = "seal_manifest"
        sidecar = Path(rel).parent / SIDECAR_NAME
        if (root / sidecar).is_file():
            roles[sidecar.as_posix()] = "provenance_sidecar"
        sap = record.get("sap")
        if isinstance(sap, str) and (root / sap).is_file():
            roles[sap] = "sap"
    for rel in _matching(root, SAP_GLOB):
        roles[rel] = "sap"
    return dict(sorted(roles.items()))


def build_manifest(root: Path = ROOT) -> dict:
    files = [
        {"path": rel, "role": role, "sha256": lf_sha256(root / rel)}
        for rel, role in select_sealed_files(root).items()
    ]
    return {
        "schema": SCHEMA,
        "hash_protocol": HASH_PROTOCOL,
        "selection_rule": SELECTION_RULE,
        "files": files,
    }


def render(manifest: dict) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_manifest(out: Path, root: Path = ROOT) -> str:
    data = render(build_manifest(root))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def proof_digest(proof: Path) -> str:
    """The SHA-256 digest a detached .ots proof commits to."""
    data = proof.read_bytes()
    if not data.startswith(OTS_MAGIC):
        raise ValueError(f"{proof}: not an OpenTimestamps proof")
    pos = len(OTS_MAGIC)
    if data[pos] != 0x01:
        raise ValueError(f"{proof}: unsupported proof version {data[pos]}")
    pos += 1
    if data[pos] != OTS_OP_SHA256:
        raise ValueError(f"{proof}: file hash is not SHA-256 (op 0x{data[pos]:02x})")
    pos += 1
    digest = data[pos:pos + 32]
    if len(digest) != 32:
        raise ValueError(f"{proof}: truncated digest")
    return digest.hex()


def verify_offline(manifest_path: Path, root: Path = ROOT) -> tuple[list[str], list[str]]:
    """Return (problems, notes). Any problem means the check failed."""
    problems: list[str] = []
    notes: list[str] = []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA:
        problems.append(f"schema is {manifest.get('schema')!r}, expected {SCHEMA!r}")
    listed = set()
    for entry in manifest.get("files", []):
        rel = entry["path"]
        listed.add(rel)
        path = root / rel
        if not path.is_file():
            problems.append(f"MISSING: {rel}")
        elif lf_sha256(path) != entry["sha256"]:
            problems.append(f"CHANGED since stamp: {rel}")
    for rel in select_sealed_files(root):
        if rel not in listed:
            notes.append(f"not in this stamp (sealed or added later): {rel}")
    proof = manifest_path.with_name(manifest_path.name + ".ots")
    if proof.is_file():
        manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        try:
            committed = proof_digest(proof)
        except ValueError as exc:
            problems.append(str(exc))
        else:
            if committed != manifest_digest:
                problems.append(
                    f"proof {proof.name} commits to {committed}, manifest is {manifest_digest}")
    else:
        notes.append(f"no proof beside the manifest ({proof.name})")
    return problems, notes


def _ots(ots_bin: str, *args: str) -> int:
    cmd = [ots_bin, *args]
    print("$ " + " ".join(cmd), file=sys.stderr)
    try:
        return subprocess.run(cmd, check=False).returncode
    except FileNotFoundError:
        print(f"ots client not found: {ots_bin}. Install opentimestamps-client=="
              f"{OTS_CLIENT_VERSION} in a virtual environment and set OTS_BIN.",
              file=sys.stderr)
        return 127


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--ots-bin", default=os.environ.get("OTS_BIN", "ots"))
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("build", "stamp", "verify"):
        p = sub.add_parser(name)
        p.add_argument("manifest", type=Path)
        if name == "verify":
            p.add_argument("--network", action="store_true",
                           help="also run `ots verify` (needs a Bitcoin node)")
    for name in ("upgrade", "info"):
        p = sub.add_parser(name)
        p.add_argument("proof", type=Path)
    args = parser.parse_args(argv)

    if args.cmd in ("build", "stamp"):
        digest = write_manifest(args.manifest, args.root)
        print(f"{args.manifest}: sha256 {digest}")
        if args.cmd == "build":
            return 0
        proof = args.manifest.with_name(args.manifest.name + ".ots")
        if proof.exists():
            print(f"refusing to overwrite existing proof {proof}", file=sys.stderr)
            return 1
        return _ots(args.ots_bin, "stamp", str(args.manifest))

    if args.cmd == "upgrade":
        rc = _ots(args.ots_bin, "upgrade", str(args.proof))
        backup = args.proof.with_name(args.proof.name + ".bak")
        if rc == 0 and backup.exists():
            backup.unlink()
        return rc

    if args.cmd == "info":
        return _ots(args.ots_bin, "info", str(args.proof))

    problems, notes = verify_offline(args.manifest, args.root)
    for note in notes:
        print(f"note: {note}")
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"{args.manifest}: every listed file matches; the proof commits to the manifest")
    if args.network:
        proof = args.manifest.with_name(args.manifest.name + ".ots")
        return _ots(args.ots_bin, "verify", "-f", str(args.manifest), str(proof))
    return 0


if __name__ == "__main__":
    sys.exit(main())
