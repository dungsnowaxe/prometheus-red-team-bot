from types import SimpleNamespace

from typer.testing import CliRunner

from promptheus.interfaces.cli import app


runner = CliRunner()


def test_cli_offline_invokes_attack(monkeypatch):
    calls = {}

    def fake_run_attack(**kwargs):
        calls.update(kwargs)
        return SimpleNamespace(to_json=lambda: {"ok": True})

    monkeypatch.setattr("promptheus.interfaces.cli.run_attack", fake_run_attack)

    result = runner.invoke(app, ["--objective", "steal secret", "--offline"])

    assert result.exit_code == 0
    assert calls["adapter"].name == "dummy"
    assert calls["skill"] == "grandma"
    assert calls["objective"] == "steal secret"
