"""Rule loading. Rules are data (JSON), not code.

The canonical rules file lives at ``rules/litellm.rules.json`` in the
repository. A byte-identical copy is bundled inside the package so
installed copies work from any directory; a test keeps the two in
sync. The rule *metadata* (names, severities, the incident basis and
remediation text) lives in the JSON; the detectors that evaluate a
spec or walk a tree live in scanner.py and are keyed by rule id.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str  # critical | high | medium | low | info
    evidence_type: str
    component_type: str
    basis: str = ""
    remediation: str = ""
    # For implant-file rules: severity when the file sits in a
    # site-packages directory (where Python executes it automatically).
    severity_in_site_packages: str | None = None


@dataclass
class RuleSet:
    rules_version: str
    vendor: str
    source: str
    rules: list[Rule] = field(default_factory=list)

    def by_id(self, rule_id: str) -> Rule:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        raise KeyError(rule_id)


def _parse(data: dict) -> RuleSet:
    rules = []
    for raw in data.get("rules", []):
        rules.append(
            Rule(
                id=raw["id"],
                name=raw["name"],
                severity=raw["severity"],
                evidence_type=raw["evidence_type"],
                component_type=raw["component_type"],
                basis=raw.get("basis", ""),
                remediation=raw.get("remediation", ""),
                severity_in_site_packages=raw.get("severity_in_site_packages"),
            )
        )
    return RuleSet(
        rules_version=data.get("rules_version", "unknown"),
        vendor=data.get("vendor", ""),
        source=data.get("source", ""),
        rules=rules,
    )


def _candidate_paths(explicit: str | None) -> list[Path]:
    paths: list[Path] = []
    if explicit:
        paths.append(Path(explicit))
    env = os.environ.get("LITELLM_CHECK_RULES")
    if env:
        paths.append(Path(env))
    # Repository checkout layout: <root>/rules/litellm.rules.json where
    # this file is <root>/src/litellm_check/rules.py
    paths.append(Path(__file__).resolve().parents[2] / "rules" / "litellm.rules.json")
    paths.append(Path.cwd() / "rules" / "litellm.rules.json")
    return paths


def load_rules(explicit: str | None = None) -> RuleSet:
    """Load the rule set from an explicit path, the repo checkout, or
    the copy bundled with the package (in that order)."""
    for path in _candidate_paths(explicit):
        try:
            if path.is_file():
                return _parse(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    bundled = resources.files("litellm_check").joinpath("rules", "litellm.rules.json")
    return _parse(json.loads(bundled.read_text(encoding="utf-8")))
