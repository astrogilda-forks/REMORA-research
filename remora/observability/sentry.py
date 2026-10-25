# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Opt-in error and performance reporting to Sentry for the REMORA API.

Off unless ``SENTRY_DSN`` is set. ``sentry-sdk`` is an optional dependency
(the ``sentry`` extra); with the DSN set and the package missing, the API
starts anyway and logs one warning: monitoring must never be the reason a
governed deployment does not run, and it never decides anything.

What leaves the process is kept to what an operator needs to find a fault,
because a governance API handles tool arguments, approvals and credentials:

* ``send_default_pii`` is off, so no client IP, user or cookie is attached;
* local variables are not captured in stack frames, so a tool argument or a
  key held in a local never reaches an event;
* request bodies are never attached, and :func:`scrub_event` removes the
  request's headers, cookies, query string and body from every event and
  every transaction before it is sent;
* traces are sampled at ``SENTRY_TRACES_SAMPLE_RATE`` (default 0: errors only).

Settings: ``SENTRY_DSN``, ``SENTRY_ENVIRONMENT`` (default ``REMORA_ENV``),
``SENTRY_RELEASE`` (default the package version), ``SENTRY_TRACES_SAMPLE_RATE``.
The default environment is ``REMORA_ENV`` as ``remora.profiles`` reads it.
The audit chain is unaffected: Sentry is an operational view, never evidence.
"""
from __future__ import annotations

import logging
import os
from typing import Any

__all__ = ["init_sentry_from_env", "scrub_event", "sentry_options"]

_LOGGER = logging.getLogger("remora.observability.sentry")
#: Request fields removed from every event before it is sent.
_REQUEST_FIELDS = ("headers", "cookies", "data", "query_string", "env")


def scrub_event(event: dict[str, Any], _hint: Any = None) -> dict[str, Any]:
    """Drop request headers, cookies, body, query string and environment."""
    request = event.get("request")
    if isinstance(request, dict):
        for field in _REQUEST_FIELDS:
            request.pop(field, None)
    event.pop("user", None)
    return event


def _deployment_environment() -> str:
    """``REMORA_ENV`` through its one parser; a value it refuses reads as unknown."""
    from remora.profiles import deployment_environment

    try:
        return deployment_environment()
    except Exception:
        return "unknown"


def _sample_rate(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        _LOGGER.warning("SENTRY_TRACES_SAMPLE_RATE %r is not a number; tracing stays off", raw)
        return 0.0
    if not 0.0 <= value <= 1.0:
        _LOGGER.warning("SENTRY_TRACES_SAMPLE_RATE %r is outside [0, 1]; tracing stays off", raw)
        return 0.0
    return value


def sentry_options(dsn: str, *, environment: str, release: str,
                   traces_sample_rate: float) -> dict[str, Any]:
    """The keyword arguments ``sentry_sdk.init`` receives."""
    return {
        "dsn": dsn,
        "environment": environment,
        "release": release,
        "send_default_pii": False,
        "include_local_variables": False,
        "max_request_body_size": "never",
        "traces_sample_rate": traces_sample_rate,
        "before_send": scrub_event,
        "before_send_transaction": scrub_event,
    }


def init_sentry_from_env(*, release: str = "") -> bool:
    """Initialise Sentry when ``SENTRY_DSN`` is set; True when it was.

    Never raises: a missing package or an SDK that refuses the DSN is logged
    and the API runs without reporting.
    """
    dsn = os.environ.get("SENTRY_DSN", "").strip()
    if not dsn:
        return False
    try:
        import sentry_sdk
    except ImportError:
        _LOGGER.warning("SENTRY_DSN is set but sentry-sdk is not installed "
                        "(pip install -e '.[sentry]'); error reporting is off")
        return False
    options = sentry_options(
        dsn,
        environment=(os.environ.get("SENTRY_ENVIRONMENT", "").strip()
                     or _deployment_environment()),
        release=os.environ.get("SENTRY_RELEASE", "").strip() or release,
        traces_sample_rate=_sample_rate(
            os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0").strip() or "0"),
    )
    try:
        sentry_sdk.init(**options)
    except Exception:
        _LOGGER.warning("sentry-sdk refused its configuration; error reporting is off",
                        exc_info=True)
        return False
    _LOGGER.info("Sentry error reporting is on (environment %s)", options["environment"])
    return True
