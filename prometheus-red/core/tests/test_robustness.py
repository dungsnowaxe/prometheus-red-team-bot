from promptheus.utils.robustness import repair_json


def test_repair_json_direct():
    data = repair_json('{"a": 1, "b": 2}')
    assert data == {"a": 1, "b": 2}


def test_repair_json_extracts_fragment():
    text = "noise {\"ok\": true} trailing"
    data = repair_json(text)
    assert data == {"ok": True}


def test_repair_json_failure():
    assert repair_json("not json") is None
