import types
import pytest


class FakeCompletion:
    def __init__(self, content: str):
        self.choices = [types.SimpleNamespace(message=types.SimpleNamespace(content=content))]


class FakeOpenAI:
    def __init__(self, response_content: str):
        self._content = response_content
        self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=self._create))

    def _create(self, *_, **__):
        return FakeCompletion(self._content)


@pytest.fixture
def fake_client_factory():
    def _factory(content: str):
        return FakeOpenAI(content)

    return _factory


@pytest.fixture
def fake_adapter():
    class Adapter:
        name = "fake-adapter"

        def __init__(self):
            self.last_payload = None

        def send_message(self, payload: str) -> str:
            self.last_payload = payload
            return f"echo:{payload}"

    return Adapter()
