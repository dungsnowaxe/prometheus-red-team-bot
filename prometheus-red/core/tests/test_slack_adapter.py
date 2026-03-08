import pytest

slack_sdk = pytest.importorskip("slack_sdk")

from promptheus.adapters.slack import SlackAdapter


def test_slack_adapter_returns_first_reply(monkeypatch):
    calls = {"post": 0, "replies": 0}

    class FakeWebClient:
        def __init__(self, token):
            calls["token"] = token

        def chat_postMessage(self, channel, text):
            calls["post"] += 1
            calls["channel"] = channel
            calls["text"] = text
            return {"ts": "123.456"}

        def conversations_replies(self, channel, ts):
            calls["replies"] += 1
            assert channel == calls["channel"]
            assert ts == "123.456"
            return {"messages": [{"ts": "123.456"}, {"ts": "123.457", "text": "bot reply"}]}

    monkeypatch.setattr("promptheus.adapters.slack.WebClient", FakeWebClient)
    monkeypatch.setattr("promptheus.adapters.slack.time.sleep", lambda *_: None)

    adapter = SlackAdapter("xoxb-1", channel="C123", poll_interval=0, max_polls=1)
    response = adapter.send_message("hi")

    assert response == "bot reply"
    assert calls["post"] == 1
    assert calls["replies"] == 1
