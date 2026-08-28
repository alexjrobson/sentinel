from typer.testing import CliRunner

from sentinel_cli.main import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "sentinel" in result.stdout


def test_scan_samples(samples_dir):
    result = runner.invoke(app, ["scan", str(samples_dir), "--case", "cli-demo"])
    assert result.exit_code == 0, result.output
    assert "findings" in result.output.lower() or "Case" in result.output
