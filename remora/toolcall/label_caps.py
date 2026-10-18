# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Label-cap vocabulary shared by the advisory and the enforcing paths.

These names live outside :mod:`remora.assess` because the module is advisory:
it says what the engine would decide if the caller's labels were true, and
nothing on the enforcing path may import it (probe P3,
tests/test_advisory_assessment_cannot_authorize.py). The cap reasons and the
risk order are enforcement vocabulary — ``/v1/assess`` and the adapters emit
them — so they sit here, next to the deployment registry they describe.
"""

from __future__ import annotations

from enum import Enum

#: Strictness order for the raise-only clamp. Anything outside this map
#: (typos, custom tiers) is never clamped — the engine's own validation
#: owns unknown tiers.
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class LabelCapReason(str, Enum):
    """Why an ACCEPT was lowered to VERIFY on the library path.

    Appended to ``DecisionReport.reasons`` and so to the envelope's
    ``policy_triggers``. The engine itself never emits these.
    """

    CALLER_LABELS_UNTRUSTED = "caller_labels_untrusted"
    TOOL_NOT_IN_REGISTRY = "tool_not_in_registry"
    REGISTRY_LABEL_CONFLICT = "registry_label_conflict"
