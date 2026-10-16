# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Both Clopper-Pearson upper bounds on one fixed grid (SDD-AS-v1 AS-016).

``remora.selective.risk_control`` and ``remora.selective.binomial_bounds``
each carry a ``clopper_pearson_upper``; the guardrail uses the second. B01
was an overflow in the first that a check of the second could not see, so
both are held to the same grid here: n in 1, 10, 500, 5000 and 100000,
delta at .05 and at the Bonferroni level .05/7, absolute tolerance 1e-10.

Reference values are SciPy's ``beta.ppf(1 - delta, k + 1, n - k)``, computed
once and pinned so the test needs no SciPy. At n = 100000 the grid stops at
k = 1000 to keep the unit suite fast; k = n/2 at n = 5000 is pinned in
``tests/test_risk_control.py``.
"""
from __future__ import annotations

import pytest

from remora.selective import binomial_bounds, risk_control

DELTA = 0.05
DELTA_BONF = 0.05 / 7
TOL = 1e-10

IMPLEMENTATIONS = [
    pytest.param(risk_control.clopper_pearson_upper, id="risk_control"),
    pytest.param(binomial_bounds.clopper_pearson_upper, id="binomial_bounds"),
]

GRID = [
    (0, 1, DELTA, 0.95),
    (0, 1, DELTA_BONF, 0.9928571428571429),
    (0, 10, DELTA, 0.2588655508930522),
    (1, 10, DELTA, 0.3941633024365047),
    (9, 10, DELTA, 0.9948838031081763),
    (0, 10, DELTA_BONF, 0.38991942615119),
    (1, 10, DELTA_BONF, 0.5242234926308634),
    (9, 10, DELTA_BONF, 0.9992834079269619),
    (0, 500, DELTA, 0.005973551516349557),
    (1, 500, DELTA, 0.009452282208075145),
    (50, 500, DELTA, 0.1248658074138089),
    (499, 500, DELTA, 0.999897418673049),
    (0, 500, DELTA_BONF, 0.009834605687541296),
    (1, 500, DELTA_BONF, 0.013963855516186887),
    (50, 500, DELTA_BONF, 0.13744311181388835),
    (499, 500, DELTA_BONF, 0.9999856631238168),
    (0, 5000, DELTA, 0.0005989670023149134),
    (1, 5000, DELTA, 0.0009484177700043886),
    (500, 5000, DELTA, 0.10725249613952188),
    (4999, 5000, DELTA, 0.9999897413937423),
    (0, 5000, DELTA_BONF, 0.0009878402487842116),
    (1, 5000, DELTA_BONF, 0.0014039721844937298),
    (500, 5000, DELTA_BONF, 0.1108452367596478),
    (4999, 5000, DELTA_BONF, 0.999998566303132),
    (0, 100000, DELTA, 2.9956874019427947e-05),
    (1, 100000, DELTA, 4.743775717389411e-05),
    (1000, 100000, DELTA, 0.010533200900636313),
    (0, 100000, DELTA_BONF, 4.941520325471352e-05),
    (1, 100000, DELTA_BONF, 7.023879222704264e-05),
    (1000, 100000, DELTA_BONF, 0.010797456399592743),
]


@pytest.mark.parametrize("upper", IMPLEMENTATIONS)
@pytest.mark.parametrize(("k", "n", "delta", "expected"), GRID)
def test_the_bound_matches_the_beta_quantile(upper, k, n, delta, expected):
    assert upper(k, n, delta) == pytest.approx(expected, abs=TOL)


@pytest.mark.parametrize("upper", IMPLEMENTATIONS)
@pytest.mark.parametrize("n", [1, 10, 500, 5000, 100000])
@pytest.mark.parametrize("delta", [DELTA, DELTA_BONF])
def test_zero_errors_match_the_closed_form(upper, n, delta):
    # P(X <= 0) = (1 - p)^n = delta  =>  p = 1 - delta^(1/n).
    assert upper(0, n, delta) == pytest.approx(1.0 - delta ** (1.0 / n), abs=TOL)


@pytest.mark.parametrize("upper", IMPLEMENTATIONS)
@pytest.mark.parametrize("n", [1, 10, 500, 5000, 100000])
@pytest.mark.parametrize("delta", [DELTA, DELTA_BONF])
def test_all_errors_bound_at_one(upper, n, delta):
    assert upper(n, n, delta) == 1.0


@pytest.mark.parametrize("upper", IMPLEMENTATIONS)
@pytest.mark.parametrize("n", [500, 5000])
def test_the_bound_is_finite_monotone_and_in_range(upper, n):
    ks = [0, 1, 2, n // 100, n // 10, n // 4, n // 2, n - 2, n - 1, n]
    bounds = [upper(k, n, DELTA) for k in ks]
    assert all(0.0 <= b <= 1.0 for b in bounds)
    assert all(a < b for a, b in zip(bounds, bounds[1:-1]))
    assert all(k / n <= b for k, b in zip(ks, bounds))


@pytest.mark.parametrize("upper", IMPLEMENTATIONS)
def test_a_stricter_delta_gives_a_wider_bound(upper):
    for k, n in [(0, 500), (50, 500), (1, 100000)]:
        assert upper(k, n, DELTA_BONF) > upper(k, n, DELTA)
