# SPDX-License-Identifier: BUSL-1.1
"""Study C statistics (plan §6): paired cluster bootstrap with a one-sided p.

``analysis.paired_cluster_difference`` gives a percentile 95 % interval. The
primary family needs a p-value per contrast for Holm, so this resamples the
same way (whole clusters, here customers) and also reports the one-sided
bootstrap p for "arm above control": ``(draws <= 0 + 1) / (n_boot + 1)``.
"""
from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from experiments.ws1_composition import analysis

SEED = 20261020


def paired_cluster_test(rows: Sequence[tuple[str, float, float]], *, n_boot: int = 10_000,
                        seed: int = SEED) -> dict[str, Any]:
    """Arm minus control over (cluster, arm value, control value) rows."""
    if not rows:
        raise ValueError("no paired rows")
    groups: dict[str, list[float]] = defaultdict(list)
    for cluster, a, b in rows:
        groups[cluster].append(a - b)
    keys = sorted(groups)
    flat = [v for k in keys for v in groups[k]]
    point = sum(flat) / len(flat)
    rng = random.Random(seed)
    draws = []
    for _ in range(n_boot):
        sample = [v for _ in keys for v in groups[keys[rng.randrange(len(keys))]]]
        draws.append(sum(sample) / len(sample))
    draws.sort()
    lo, hi = draws[int(0.025 * n_boot)], draws[int(0.975 * n_boot) - 1]
    p = (sum(d <= 0 for d in draws) + 1) / (n_boot + 1)
    return {**analysis.interval_report(point, lo, hi), "p_one_sided": p,
            "clusters": len(keys), "rows": len(rows), "n_boot": n_boot, "seed": seed}


def primary_family(tests: Mapping[str, Mapping[str, Any] | None], *,
                   alpha: float = 0.05) -> dict[str, Any]:
    """Holm over the primary contrasts. A missing contrast is not testable and
    is never counted as a rejection."""
    present = {k: float(v["p_one_sided"]) for k, v in tests.items() if v is not None}
    rejected = analysis.holm(present, alpha) if present else {}
    return {"alpha": alpha, "method": "Holm over one-sided cluster-bootstrap p",
            "rejected": {k: rejected.get(k, False) for k in tests},
            "not_testable": sorted(k for k, v in tests.items() if v is None)}
