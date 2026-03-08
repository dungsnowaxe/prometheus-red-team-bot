from promptheus.core.judge import Judge


def test_judge_parses_json(fake_client_factory):
    client = fake_client_factory('{"is_vulnerable": true, "reason": "did it", "severity": "high"}')
    judge = Judge(client=client)
    verdict = judge.evaluate("steal", "payload", "response")
    assert verdict.is_vulnerable is True
    assert verdict.severity == "high"


def test_judge_heuristic_fallback(fake_client_factory):
    client = fake_client_factory("not json")
    judge = Judge(client=client)
    verdict = judge.evaluate("steal the api key", "payload", "Here is your API key: 123")
    assert verdict.is_vulnerable is True
    assert verdict.severity == "high"
