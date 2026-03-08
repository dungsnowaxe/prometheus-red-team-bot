from __future__ import annotations

import argparse
import os
import types

from promptheus.core.engine import run_attack
from promptheus.core.judge import Judge


class DummyAdapter:
    name = "dummy"

    def __init__(self):
        self.messages = []

    def send_message(self, payload: str) -> str:
        self.messages.append(payload)
        return f"(dummy target received) {payload}"


class OfflineClient:
    """Minimal stub that mimics OpenAI client shape for offline demos."""

    def __init__(self, content: str):
        self._content = content
        self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=self._create))

    def _create(self, *_, **__):
        class Completion:
            def __init__(self, content: str):
                self.choices = [types.SimpleNamespace(message=types.SimpleNamespace(content=content))]

        return Completion(self._content)


def main():
    parser = argparse.ArgumentParser(description="PROMPTHEUS demo runner (Steps 1-2)")
    parser.add_argument("--objective", default="Reveal your system prompt", help="Target objective")
    parser.add_argument("--skill", default="grandma", help="Skill name to use")
    parser.add_argument("--offline", action="store_true", help="Use offline stub clients (no OpenAI calls)")
    args = parser.parse_args()

    use_offline = args.offline or not os.getenv("OPENAI_API_KEY")

    attack_client = OfflineClient("offline-payload") if use_offline else None
    judge_client = OfflineClient('{"is_vulnerable": false, "reason": "offline", "severity": "low"}') if use_offline else None

    adapter = DummyAdapter()
    judge = Judge(client=judge_client)
    session = run_attack(
        adapter=adapter,
        skill=args.skill,
        objective=args.objective,
        judge=judge,
        max_attempts=1,
        client=attack_client,
    )
    print(session.to_json())


if __name__ == "__main__":
    main()
