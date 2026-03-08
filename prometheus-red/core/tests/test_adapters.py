import types

import pytest

from promptheus.adapters.local import LocalFunctionAdapter
from promptheus.adapters.rest import RestAdapter


def test_local_function_adapter_invokes_callable():
    def echo(payload: str) -> str:
        return payload.upper()

    adapter = LocalFunctionAdapter(echo)
    assert adapter.send_message("hi") == "HI"
    assert adapter.name == "echo"


def test_rest_adapter_posts_json(monkeypatch):
    calls = {}

    class FakeResponse:
        status_code = 200
        text = "ok"

        def raise_for_status(self):
            return None

        def json(self):
            return {"echo": "ok"}

    def fake_post(url, json=None, headers=None, timeout=None):
        calls["url"] = url
        calls["json"] = json
        calls["headers"] = headers
        calls["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("requests.post", fake_post)

    adapter = RestAdapter("http://example.com/api", headers={"X": "1"}, timeout=1, payload_field="msg")
    response = adapter.send_message("hello")

    assert response == "ok"
    assert calls["url"] == "http://example.com/api"
    assert calls["json"] == {"msg": "hello"}
    assert calls["headers"] == {"X": "1"}
    assert calls["timeout"] == 1
