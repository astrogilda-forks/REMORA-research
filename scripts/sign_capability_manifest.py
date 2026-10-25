#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Sign, verify or digest a Capability Activation Manifest (SDD §3, ADR-UE-03).

The deployment's policy owner signs the manifest offline with an Ed25519 key;
the REMORA host holds only the public key (``REMORA_CAM_TRUSTED_KEYS``), so it
can verify the manifest and cannot author one. Run the signing step where the
key is kept, never on the REMORA host.

    REMORA_CAM_SIGNING_SEED=<64 hex or base64> \\
        python scripts/sign_capability_manifest.py manifest.yaml --out cam.json
    python scripts/sign_capability_manifest.py --new-key      # a fresh seed and its public key
    python scripts/sign_capability_manifest.py --verify cam.json --trusted-keys <hex>[,<hex>]
    python scripts/sign_capability_manifest.py --digest manifest.yaml

The input is a plain ``capability-activation/v1`` manifest (JSON or YAML) and
is parsed before signing, so an envelope never carries a manifest REMORA would
refuse to load. ``--verify`` prints the digest and the signer's key id and
exits 1 on any refusal; ``--digest`` prints the canonical digest of a plain
manifest, which is what later slices pin as ``cam_digest``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _read(path: str):
    import yaml

    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    from remora.crypto import SignatureDomain, SigningKey
    from remora.governance.activation_manifest import (
        CapabilityManifest,
        ManifestError,
        load_manifest,
        sign_manifest,
        trusted_keys_from_text,
    )

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("manifest", nargs="?", help="a plain manifest to sign or digest")
    parser.add_argument("--out", help="where the signed envelope is written")
    parser.add_argument("--new-key", action="store_true")
    parser.add_argument("--verify", metavar="ENVELOPE", help="verify a signed envelope")
    parser.add_argument("--trusted-keys", default="", help="public keys for --verify")
    parser.add_argument("--digest", action="store_true", help="print the canonical digest")
    args = parser.parse_args(argv)
    domains = {SignatureDomain.CAPABILITY_MANIFEST}

    if args.new_key:
        key = SigningKey.generate(domains)
        print(json.dumps({"seed": key.seed.hex(),
                          "public_key": key.verification_key().public_bytes.hex()}))
        return 0

    if args.verify:
        try:
            loaded = load_manifest(_read(args.verify),
                                   trusted_keys=trusted_keys_from_text(args.trusted_keys),
                                   strict=True)
        except (ManifestError, ValueError, OSError) as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({"deployment": loaded.manifest.deployment,
                          "capabilities": len(loaded.manifest.entries),
                          "digest": loaded.manifest.digest, "signer_kid": loaded.signer_kid}))
        return 0

    if not args.manifest:
        parser.error("a manifest is required")
    try:
        manifest = CapabilityManifest.from_dict(_read(args.manifest))
    except (ManifestError, OSError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    if args.digest:
        print(manifest.digest)
        return 0
    if not args.out:
        parser.error("--out is required to sign")
    seed = os.environ.get("REMORA_CAM_SIGNING_SEED", "").strip()
    if not seed:
        parser.error("REMORA_CAM_SIGNING_SEED is not set")
    key = SigningKey.from_text(seed, domains)
    signed_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    document = sign_manifest(manifest.to_dict(), key, signed_at)
    Path(args.out).write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                              encoding="utf-8")
    print(f"digest {manifest.digest}; public key to trust: "
          f"{key.verification_key().public_bytes.hex()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
