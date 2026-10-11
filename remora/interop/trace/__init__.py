# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""REMORA as an AgenTrust TRACE external-evidence-source (mapping only, no Trust Record)."""

from .mapping import (
    EAT_PROFILE,
    MAPPING_SCHEMA,
    REFERENCE_REL,
    TRACE_REQUIRED,
    ExportRequest,
    TraceExportRefused,
    map_result,
)

__all__ = ["EAT_PROFILE", "MAPPING_SCHEMA", "REFERENCE_REL", "TRACE_REQUIRED", "ExportRequest",
           "TraceExportRefused", "map_result"]
