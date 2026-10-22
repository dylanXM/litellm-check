import json
from pathlib import Path

from litellm_check.report import render_json, render_markdown
from litellm_check.rules import load_rules
from litellm_check.scanner import scan_path

FIXTURES = Path(__file__).parent / "fixtures"


def _result():
    return scan_path(FIXTURES / "positive", load_rules())


def test_markdown_report_structure():
    md = render_markdown(_result(), load_rules())
    assert "# LiteLLM v1.107.0 Exposure Check" in md
    assert "Incident summary" in md
    assert "docs.litellm.ai/blog/security-incident-oct-21-2026" in md
    assert "## Detection limits" in md
    # the honesty clause: never a clean bill of health
    assert "does not prove the environment is clean" in md
    assert "vendor response steps" in md
    assert "cook.pth" in md


def test_json_report_structure():
    data = json.loads(render_json(_result(), load_rules()))
    assert data["tool"]["name"] == "litellm-check"
    assert data["tool"]["version"] == "0.1.0"
    assert data["incident"]["affected_version"] == "1.107.0"
    assert data["incident"]["compromised_image_digest"].startswith(
        "sha256:1bbcb144")
    assert data["summary"]["total_findings"] == len(data["findings"])
    assert data["summary"]["by_severity"]["critical"] >= 10
    assert data["vendor_response_steps"]
    assert "does not prove" in data["limitations"]
    first = data["findings"][0]
    assert first["evidence"]["source_file"]
    assert first["incident_basis"]
