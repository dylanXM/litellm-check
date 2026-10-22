from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_bundled_rules_match_repo_rules():
    repo = (ROOT / "rules" / "litellm.rules.json").read_bytes()
    bundled = (ROOT / "src" / "litellm_check" / "rules"
               / "litellm.rules.json").read_bytes()
    assert repo == bundled
