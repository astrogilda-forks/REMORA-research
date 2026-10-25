# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Opt-in Sentry reporting (remora/observability/sentry.py).

Pinned: nothing initialises without ``SENTRY_DSN``; a missing package or an
SDK that refuses the DSN never raises; the options keep personal data, local
variables and request bodies out; every event and transaction loses its
request headers, cookies, body, query string and user before it is sent; the
sample rate is bounded; the API module calls the initialiser at import.
"""
from __future__ import annotations

import sys
import types

import pytest

from remora.observability import sentry as rs


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for name in ("SENTRY_DSN", "SENTRY_ENVIRONMENT", "SENTRY_RELEASE",
                 "SENTRY_TRACES_SAMPLE_RATE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def fake_sdk(monkeypatch):
    calls: list[dict] = []
    module = types.ModuleType("sentry_sdk")
    module.init = lambda **kw: calls.append(kw)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentry_sdk", module)
    return calls


def test_without_a_dsn_nothing_is_initialised(fake_sdk):
    assert rs.init_sentry_from_env() is False
    assert fake_sdk == []


def test_a_blank_dsn_is_unset(fake_sdk, monkeypatch):
    monkeypatch.setenv("SENTRY_DSN", "   ")
    assert rs.init_sentry_from_env() is False and fake_sdk == []


def test_with_a_dsn_the_sdk_gets_the_privacy_preserving_options(fake_sdk, monkeypatch):
    monkeypatch.setenv("SENTRY_DSN", "https://public@o1.ingest.example/1")
    monkeypatch.setenv("REMORA_ENV", "production")
    assert rs.init_sentry_from_env(release="0.12.0") is True
    (options,) = fake_sdk
    assert options["dsn"] == "https://public@o1.ingest.example/1"
    assert options["environment"] == "production"
    assert options["release"] == "0.12.0"
    assert options["send_default_pii"] is False
    assert options["include_local_variables"] is False
    assert options["max_request_body_size"] == "never"
    assert options["traces_sample_rate"] == 0.0
    assert options["before_send"] is rs.scrub_event
    assert options["before_send_transaction"] is rs.scrub_event


def test_explicit_environment_release_and_sample_rate_win(fake_sdk, monkeypatch):
    monkeypatch.setenv("SENTRY_DSN", "https://public@o1.ingest.example/1")
    monkeypatch.setenv("SENTRY_ENVIRONMENT", "ot-pilot")
    monkeypatch.setenv("SENTRY_RELEASE", "remora@abc123")
    monkeypatch.setenv("SENTRY_TRACES_SAMPLE_RATE", "0.25")
    assert rs.init_sentry_from_env(release="0.12.0") is True
    assert (fake_sdk[0]["environment"], fake_sdk[0]["release"],
            fake_sdk[0]["traces_sample_rate"]) == ("ot-pilot", "remora@abc123", 0.25)


@pytest.mark.parametrize("raw", ["fast", "1.5", "-0.1", "nan"])
def test_a_bad_sample_rate_leaves_tracing_off(fake_sdk, monkeypatch, raw):
    monkeypatch.setenv("SENTRY_DSN", "https://public@o1.ingest.example/1")
    monkeypatch.setenv("SENTRY_TRACES_SAMPLE_RATE", raw)
    assert rs.init_sentry_from_env() is True
    assert fake_sdk[0]["traces_sample_rate"] == 0.0


def test_a_missing_package_is_a_warning_not_a_failure(monkeypatch, caplog):
    monkeypatch.setenv("SENTRY_DSN", "https://public@o1.ingest.example/1")
    monkeypatch.setitem(sys.modules, "sentry_sdk", None)   # import raises ImportError
    with caplog.at_level("WARNING", logger="remora.observability.sentry"):
        assert rs.init_sentry_from_env() is False
    assert "sentry-sdk is not installed" in caplog.text


def test_an_sdk_that_refuses_the_dsn_is_a_warning_not_a_failure(monkeypatch, caplog):
    module = types.ModuleType("sentry_sdk")

    def refuse(**_kw):
        raise ValueError("bad dsn")

    module.init = refuse  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentry_sdk", module)
    monkeypatch.setenv("SENTRY_DSN", "not-a-dsn")
    with caplog.at_level("WARNING", logger="remora.observability.sentry"):
        assert rs.init_sentry_from_env() is False
    assert "refused its configuration" in caplog.text


def test_scrub_removes_request_data_and_the_user_and_keeps_the_rest():
    event = {
        "exception": {"values": [{"type": "RuntimeError"}]},
        "request": {"url": "https://api.example/v1/execution/execute", "method": "POST",
                    "headers": {"Authorization": "Bearer ot-agent"},
                    "cookies": {"s": "x"}, "data": {"arguments": {"iban": "NO93"}},
                    "query_string": "token=x", "env": {"REMOTE_ADDR": "10.0.0.1"}},
        "user": {"ip_address": "10.0.0.1"},
        "tags": {"route": "/v1/execution/execute"},
    }
    scrubbed = rs.scrub_event(event)
    assert scrubbed["request"] == {"url": "https://api.example/v1/execution/execute",
                                   "method": "POST"}
    assert "user" not in scrubbed
    assert scrubbed["exception"]["values"][0]["type"] == "RuntimeError"
    assert scrubbed["tags"] == {"route": "/v1/execution/execute"}
    assert rs.scrub_event({"message": "no request"}) == {"message": "no request"}


def test_the_real_sdk_accepts_the_options_when_it_is_installed():
    sentry_sdk = pytest.importorskip("sentry_sdk")
    options = rs.sentry_options("", environment="test", release="r", traces_sample_rate=0.0)
    sentry_sdk.init(**options)   # an empty DSN disables sending; the options must be valid
    sentry_sdk.init()            # reset


def test_the_api_initialises_sentry_at_import():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "servers" / "api.py").read_text(encoding="utf-8")
    assert "_init_sentry(release=_PACKAGE_VERSION)" in source
