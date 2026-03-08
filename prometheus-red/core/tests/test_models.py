from promptheus.core.models import AttackAttempt, AttackResult, AttackSession, JudgeVerdict


def test_session_round_trip():
    attempt = AttackAttempt(skill="grandma", objective="steal", payload="do it")
    verdict = JudgeVerdict(is_vulnerable=True, reason="complied", severity="high")
    result = AttackResult(attempt=attempt, verdict=verdict)
    session = AttackSession(target="dummy", objective="steal", attempts=[result])

    data = session.to_json()
    assert data["target"] == "dummy"
    assert data["attempts"][0]["verdict"]["is_vulnerable"] is True
    assert "session_id" in data
