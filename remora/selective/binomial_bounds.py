# SPDX-License-Identifier: BUSL-1.1
"""Finite-sample binomial bounds (stdlib only).

These are used to construct conservative upper confidence bounds on
empirical risk in conformal selective prediction.
"""
from __future__ import annotations
import math


def _log_binomial_coef(n: int, k: int) -> float:
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def _binomial_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k), summed directly: sum_{i=0}^{k} C(n,i) p^i (1-p)^{n-i}."""
    if k < 0:
        return 0.0
    if k >= n or p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    log_p = math.log(p)
    log_q = math.log1p(-p)
    total = 0.0
    for i in range(0, k + 1):
        total += math.exp(_log_binomial_coef(n, i) + i * log_p + (n - i) * log_q)
    return min(1.0, total)


def binomial_tail_prob(k: int, n: int, p: float) -> float:
    """P(X >= k) where X ~ Binomial(n, p). Exact via direct log-sum.

    Computed as sum_{i=k}^{n} C(n,i) p^i (1-p)^{n-i} using log-gamma for
    numerical stability. The cost is O(n - k); clopper_pearson_upper picks
    whichever of this and the CDF has fewer terms.
    """
    if k > n:
        return 0.0
    if k <= 0:
        return 1.0
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0  # k <= n is established above
    log_p = math.log(p)
    log_q = math.log1p(-p)
    total = 0.0
    for i in range(k, n + 1):
        log_term = _log_binomial_coef(n, i) + i * log_p + (n - i) * log_q
        total += math.exp(log_term)
    return min(1.0, total)


def clopper_pearson_upper(k: int, n: int, alpha: float = 0.05) -> float:
    """Upper end of Clopper-Pearson exact interval for a proportion.

    Returns the LARGEST p* such that P(X <= k | Binomial(n, p*)) >= alpha
    (P(X <= k) is decreasing in p, so this is the crossing point where it
    falls to alpha). Uses binary search over p in [0, 1].

    Interpretation: the true error rate exceeds the returned value with
    probability at most alpha.

    P(X <= k) is summed on whichever side of the distribution has fewer
    terms, so one evaluation costs O(min(k, n - k)). The bound agrees with
    SciPy's beta quantile to 1e-10 from n = 1 to n = 100000
    (tests/test_binomial_bound_grid.py).
    """
    if k == n:
        return 1.0
    if k < 0:
        return 0.0

    lo = 0.0
    hi = 1.0

    for _ in range(100):
        mid = (lo + hi) / 2.0

        if k + 1 <= n - k:
            prob_less_eq_k = _binomial_cdf(k, n, mid)
        else:
            # P(X <= k | mid) = 1 - P(X >= k+1 | mid)
            prob_less_eq_k = 1.0 - binomial_tail_prob(k + 1, n, mid)

        if prob_less_eq_k < alpha:
            # mid is too large, the probability of <= k is too small
            hi = mid
        else:
            lo = mid

        if hi - lo < 1e-10:
            break

    return hi


def risk_upper_confidence_bound(
    wrong: int, accepted: int, alpha: float = 0.05
) -> float | None:
    """Upper 1-alpha confidence bound on the empirical risk wrong/accepted.

    Returns None if accepted == 0.
    Returns clopper_pearson_upper(wrong, accepted, alpha).
    """
    if accepted == 0:
        return None
    return clopper_pearson_upper(wrong, accepted, alpha)
