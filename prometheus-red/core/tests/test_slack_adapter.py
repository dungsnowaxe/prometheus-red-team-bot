import pytest

slack_sdk = pytest.importorskip("slack_sdk")

from promptheus.adapters.slack import SlackAdapter


def test_slack_adapter_returns_first_reply(monkeypatch):
    calls = {"post": 0, "replies": 0}

    class FakeWebClient:
        def chat_postMessage(self, channel, thread_ts, text):
            calls["post"] += 1
            calls["channel"] = channel
            calls["thread_ts"] = thread_ts
            calls["text"] = text
            return {"ok": True, "ts": "123.456"}

        def conversations_replies(self, channel, ts, limit=200):
            calls["replies"] += 1
            assert channel == calls["channel"]
            assert ts == calls["thread_ts"]
            return {"ok": True, "messages": [{"ts": "123.456"}, {"ts": "123.457", "text": "bot reply"}]}

    monkeypatch.setattr("promptheus.adapters.slack.time.sleep", lambda *_: None)

    adapter = SlackAdapter(FakeWebClient(), channel_id="C123", thread_ts="123.456", poll_interval=0, poll_timeout=0.01)
    response = adapter.send_message("hi")

    assert response == "bot reply"
    assert calls["post"] == 1
    assert calls["replies"] == 1
