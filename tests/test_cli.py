from pathlib import Path

from litellm_check.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_scan_stdout(capsys):
    rc = main(["scan", str(FIXTURES / "positive")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "LL-001" in out


def test_cli_fail_on_critical_positive():
    assert main(["scan", str(FIXTURES / "positive"),
                 "--fail-on", "critical"]) == 1


def test_cli_fail_on_high_negative_passes():
    # negative fixture carries only info findings
    assert main(["scan", str(FIXTURES / "negative"),
                 "--fail-on", "high"]) == 0


def test_cli_out_file(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["scan", str(FIXTURES / "positive"),
               "--format", "json", "--out", str(out)])
    assert rc == 0
    assert '"litellm-check"' in out.read_text()


def test_cli_bad_path():
    assert main(["scan", "/nonexistent-dir-xyz"]) == 2
