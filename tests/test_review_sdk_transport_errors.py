# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Review findings: post-send transport failures during execute are unknown, not retryable."""
from __future__ import annotations

import asyncio

import pytest

httpx = pytest.importorskip("httpx")

from remora.sdk import (  # noqa: E402
    AsyncRemoraClient,
    RemoraClient,
    RemoraError,
    RemoraUnavailableError,
    ToolCall,
    UnknownExecutionStateError,
)

CALL = ToolCall(tool_name="t", arguments={}, target_environment="staging")
TOKEN = {"jti": "j"}


def _sync(handler) -> RemoraClient:
    return RemoraClient(
        base_url="http://r.test", token="t",
        http_client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://r.test"),
    )


def _async(handler) -> AsyncRemoraClient:
    return AsyncRemoraClient(
        base_url="http://r.test", token="t",
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://r.test"
        ),
    )


def _raiser(exc):
    def handler(request):
        raise exc

    return handler


POST_SEND = [httpx.ReadTimeout("slow"), httpx.RemoteProtocolError("closed")]


@pytest.mark.parametrize("exc", POST_SEND)
def test_sync_execute_post_send_error_is_unknown_state(exc):
    c = _sync(_raiser(exc))
    with pytest.raises(UnknownExecutionStateError) as e:
        c.execute("item", CALL)
    assert e.value.retryable is False
    with pytest.raises(UnknownExecutionStateError):
        c.execute_accepted(TOKEN, CALL)


@pytest.mark.parametrize("exc", POST_SEND)
def test_async_execute_post_send_error_is_unknown_state(exc):
    c = _async(_raiser(exc))
    with pytest.raises(UnknownExecutionStateError):
        asyncio.run(c.execute("item", CALL))
    with pytest.raises(UnknownExecutionStateError):
        asyncio.run(c.execute_accepted(TOKEN, CALL))


def test_connect_error_stays_unavailable_for_execute():
    c = _sync(_raiser(httpx.ConnectError("refused")))
    with pytest.raises(RemoraUnavailableError):
        c.execute("item", CALL)
    ca = _async(_raiser(httpx.ConnectError("refused")))
    with pytest.raises(RemoraUnavailableError):
        asyncio.run(ca.execute("item", CALL))


def test_non_execute_read_timeout_stays_unavailable():
    c = _sync(_raiser(httpx.ReadTimeout("slow")))
    with pytest.raises(RemoraUnavailableError):
        c.assess(CALL)


def test_non_json_2xx_body_is_typed():
    c = _sync(lambda r: httpx.Response(200, content=b"<html>"))
    with pytest.raises(RemoraError):
        c.assess(CALL)
    ca = _async(lambda r: httpx.Response(200, content=b"<html>"))
    with pytest.raises(RemoraError):
        asyncio.run(ca.assess(CALL))


def test_non_dict_error_body_is_typed():
    c = _sync(lambda r: httpx.Response(500, json=["boom"]))
    with pytest.raises(RemoraError):
        c.assess(CALL)


def test_unknown_decision_value_is_typed():
    body = {
        "proposal_id": "p",
        "decision": "frobnicate",
        "audit": {"sequence_no": 0, "entry_hash": "d" * 64},
    }
    c = _sync(lambda r: httpx.Response(200, json=body))
    with pytest.raises(RemoraError):
        c.assess(CALL)


# Review 2026-10-26: a read timeout on a non-execution POST (approve, reject,
# record an effect, resolve a limit) was RemoraUnavailableError with
# retryable=True although the request may already have been applied.

APPLIED_MAYBE = [
    ("approve", lambda c: c.approve("item")),
    ("reject", lambda c: c.reject("item", reason="no")),
    ("resolve_unknown", lambda c: c.resolve_unknown("op", executed=False,
                                                    evidence_ref="plant-log:t:r", reason="r")),
]


@pytest.mark.parametrize("exc", POST_SEND)
@pytest.mark.parametrize(("name", "call"), APPLIED_MAYBE)
def test_a_post_send_failure_on_a_state_changing_call_is_not_retryable(exc, name, call):
    with pytest.raises(RemoraUnavailableError) as e:
        call(_sync(_raiser(exc)))
    assert e.value.retryable is False, name
    assert "read its state before sending it again" in str(e.value)


@pytest.mark.parametrize("exc", POST_SEND)
def test_the_async_client_classifies_the_same_way(exc):
    with pytest.raises(RemoraUnavailableError) as e:
        asyncio.run(_async(_raiser(exc)).approve("item"))
    assert e.value.retryable is False


def test_a_connect_failure_on_a_state_changing_call_stays_retryable():
    with pytest.raises(RemoraUnavailableError) as e:
        _sync(_raiser(httpx.ConnectError("refused"))).approve("item")
    assert e.value.retryable is True


def test_a_read_timeout_on_a_get_stays_retryable():
    with pytest.raises(RemoraUnavailableError) as e:
        _sync(_raiser(httpx.ReadTimeout("slow"))).get_proposal("p")
    assert e.value.retryable is True


def test_the_class_default_is_unchanged():
    assert RemoraUnavailableError.retryable is True
