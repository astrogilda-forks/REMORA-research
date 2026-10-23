#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Sign a cumulative-limit policy with the authority's Ed25519 key.

The authority that sets budgets and equipment limits signs the policy
offline; the REMORA host holds only the public key
(``REMORA_LIMITS_TRUSTED_KEYS``), so it can verify the limits but not write
itself larger ones. Run this where the key is kept, never on the REMORA host.

    REMORA_LIMITS_SIGNING_SEED=<64 hex or base64> \\
        python scripts/sign_limit_policy.py policy.json --out limits.json
    python scripts/sign_limit_policy.py --new-key     # print a fresh seed and its public key

The input is a plain ``remora-cumulative-limits/v1`` policy (JSON or YAML)
and is validated before signing. The output is the signed envelope. The
public key to trust is printed on stderr.
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


def main(argv: list[str] | None = None) -> int:
    from remora.crypto import SignatureDomain, SigningKey
    from remora.enforcement.cumulative_limits import LimitPolicy, sign_policy

    parser = argparse.ArgumentParser()
    parser.add_argument("policy", nargs="?")
    parser.add_argument("--out")
    parser.add_argument("--new-key", action="store_true")
    args = parser.parse_args(argv)
    domains = {SignatureDomain.LIMIT_POLICY}
    if args.new_key:
        key = SigningKey.generate(domains)
        print(json.dumps({"seed": key.seed.hex(),
                          "public_key": key.verification_key().public_bytes.hex()}))
        return 0
    if not args.policy or not args.out:
        parser.error("policy and --out are required")
    seed = os.environ.get("REMORA_LIMITS_SIGNING_SEED", "").strip()
    if not seed:
        parser.error("REMORA_LIMITS_SIGNING_SEED is not set")
    import yaml

    body = yaml.safe_load(Path(args.policy).read_text(encoding="utf-8"))
    LimitPolicy.from_dict(body)  # refuse to sign a policy REMORA would refuse to load
    key = SigningKey.from_text(seed, domains)
    signed_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    document = sign_policy(body, key, signed_at)
    Path(args.out).write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                              encoding="utf-8")
    print(f"public key to trust: {key.verification_key().public_bytes.hex()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
