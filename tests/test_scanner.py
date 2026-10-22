from pathlib import Path

from litellm_check.rules import load_rules
from litellm_check.scanner import scan_path

FIXTURES = Path(__file__).parent / "fixtures"
ALL_RULES = {f"LL-{i:03d}" for i in range(1, 14)}


def _rule_ids(result):
    return {f.rule_id for f in result.findings}


def test_positive_fixture_triggers_every_rule():
    result = scan_path(FIXTURES / "positive", load_rules())
    assert _rule_ids(result) == ALL_RULES


def test_positive_findings_have_evidence():
    result = scan_path(FIXTURES / "positive", load_rules())
    content = [f for f in result.findings if f.line is not None]
    assert content, "expected line-level evidence"
    for f in content:
        assert f.file and f.line >= 1 and f.snippet
    pin = [f for f in result.findings
           if f.rule_id == "LL-001" and f.file == "requirements.txt"]
    assert pin and pin[0].line == 1


def test_findings_sorted_by_severity():
    result = scan_path(FIXTURES / "positive", load_rules())
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranks = [order[f.severity] for f in result.findings]
    assert ranks == sorted(ranks)
    assert result.findings[0].severity == "critical"


def test_implant_files_critical_in_site_packages():
    result = scan_path(FIXTURES / "positive", load_rules())
    implants = [f for f in result.findings
                if f.rule_id in ("LL-009", "LL-010", "LL-011")]
    assert implants and all(f.severity == "critical" for f in implants)


def test_negative_fixture_has_no_actionable_findings():
    result = scan_path(FIXTURES / "negative", load_rules())
    actionable = [f for f in result.findings if f.severity != "info"]
    assert actionable == []
    # coverage really ran: the safe pins are reported as info
    assert _rule_ids(result) == {"LL-004", "LL-013"}
    assert result.files_scanned >= 5


def test_empty_tree_is_clean(tmp_path):
    result = scan_path(tmp_path, load_rules())
    assert result.findings == []


def test_sitecustomize_outside_site_packages_is_high_not_critical(tmp_path):
    (tmp_path / "sitecustomize.py").write_text("# user module\n")
    result = scan_path(tmp_path, load_rules())
    hits = [f for f in result.findings if f.rule_id == "LL-010"]
    assert hits and hits[0].severity == "high"


def test_spec_excluding_affected_version_is_info(tmp_path):
    (tmp_path / "requirements.txt").write_text("litellm>=1.0,!=1.107.0\n")
    result = scan_path(tmp_path, load_rules())
    assert _rule_ids(result) == {"LL-004"}


def test_digest_in_arbitrary_text_file_is_critical(tmp_path):
    (tmp_path / "notes.md").write_text(
        "we pulled sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715"
        "fb6c664cdd3ac126c339e last week\n")
    result = scan_path(tmp_path, load_rules())
    assert _rule_ids(result) == {"LL-005"}


def test_clean_digest_pinned_image_is_not_flagged(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM ghcr.io/berriai/litellm@sha256:"
        + "0" * 64 + "\n")
    result = scan_path(tmp_path, load_rules())
    assert result.findings == []
