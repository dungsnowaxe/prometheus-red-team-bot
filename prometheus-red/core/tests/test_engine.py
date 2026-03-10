from pathlib import Path

from promptheus.core.attack_runner import run_attack
from promptheus.core.judge import Judge


class VulnerableJudge(Judge):
    def __init__(self):
        super().__init__(client=None)

    def evaluate(self, objective: str, payload: str, response: str):  # type: ignore[override]
        from promptheus.core.models import JudgeVerdict

        return JudgeVerdict(is_vulnerable=True, reason="forced", severity="high")


def test_run_attack_writes_session(fake_adapter, fake_client_factory, tmp_path):
    attack_client = fake_client_factory("crafted-payload")
    judge = VulnerableJudge()

    session = run_attack(
        adapter=fake_adapter,
        skill="grandma",
        objective="steal config",
        judge=judge,
        max_attempts=2,
        client=attack_client,
        session_dir=tmp_path,
    )

    assert len(session.attempts) == 1  # early stop on vulnerability
    files = list(Path(tmp_path).glob("*.json"))
    assert files, "Session file should be written"
    content = files[0].read_text()
    assert "steal config" in content
    assert "crafted-payload" in fake_adapter.last_payload
