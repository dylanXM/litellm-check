"""Report rendering: Markdown evidence report + JSON.

Every report carries the incident summary (from the vendor's
announcement), the vendor's response steps, and a detection-limits
statement. The wording is deliberate: findings are evidence collected
against a published indicator set; a scan with no findings is NOT a
statement that an environment is safe or clean - the announcement
itself warns that not finding an indicator does not prove an
environment is clean.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from . import __version__, incident
from .rules import RuleSet
from .scanner import SEVERITY_ORDER, ScanResult

INCIDENT_SUMMARY = (
    "On 2026-10-21, LiteLLM's release pipeline was compromised and "
    "v1.107.0 was pushed to PyPI and the container registries with "
    "compiled malware that steals credentials and loads remote code. "
    "Per the official announcement "
    f"({incident.SOURCE_URL}, last updated {incident.SOURCE_UPDATED}): "
    f"the PyPI release litellm==1.107.0 was live "
    f"{incident.PYPI_WINDOW}; the Docker Hub tags v1.107.0, latest, "
    "main-latest and main-stable pointed at a compromised image index "
    f"{incident.DOCKER_WINDOW}; the same tags on GHCR were compromised "
    f"{incident.GHCR_WINDOW}. All previous versions are stated to be "
    "safe, the impacted artifacts have been pulled, and enterprise "
    "customers on the private enterprise registry were not impacted. "
    "Every rule in this tool derives from that announcement; no "
    "third-party indicators are used."
)

LIMITATIONS = (
    "This tool checks a fixed, published set of indicators taken from "
    "LiteLLM's official incident announcement: dependency specs and "
    "lockfiles that pin, admit or exclude litellm==1.107.0; container "
    "image tags and digests named in the announcement; installed "
    "litellm distribution metadata; and the implant/marker filenames "
    "the announcement lists (cook.pth, cook.py, sitecustomize.py, "
    "their compiled caches, litellm-1.107.0.dist-info, "
    "remote_code_loader.lock).\n\n"
    "It cannot detect: installs that left no artifact in the scanned "
    "tree (environments rebuilt or deleted after exposure); images "
    "pulled and run without any definition file in the tree; exposure "
    "recorded only in CI logs, shell history or registry audit logs; "
    "files renamed away from the announced names; or compromise of "
    "secrets that were reachable from an affected host (only rotation "
    "addresses that).\n\n"
    "Severity wording follows the announcement: findings marked "
    "critical are the artifacts the vendor says to treat as "
    "compromised; 'admits'-style findings (LL-003, LL-007) mark "
    "exposure surface whose impact depends on when an install or pull "
    "happened relative to the announced windows - they are not proof "
    "that the malicious artifact was installed.\n\n"
    "A report without findings means only that none of the announced "
    "indicators were found in the scanned tree. Quoting the "
    "announcement: not finding an indicator 'does not prove the "
    "environment is clean'. This tool is an evidence-collection aid "
    "for the LiteLLM v1.107.0 incident; it is not a security "
    "certification, and it never declares an environment safe."
)


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_json_dict(result: ScanResult, ruleset: RuleSet) -> dict:
    counts = result.counts_by_severity()
    return {
        "tool": {"name": "litellm-check", "version": __version__},
        "rules_version": ruleset.rules_version,
        "incident": {
            "source": incident.SOURCE_URL,
            "source_title": incident.SOURCE_TITLE,
            "source_updated": incident.SOURCE_UPDATED,
            "affected_package": incident.PACKAGE,
            "affected_version": incident.AFFECTED_VERSION,
            "pypi_window_utc": incident.PYPI_WINDOW,
            "docker_window_utc": incident.DOCKER_WINDOW,
            "ghcr_window_utc": incident.GHCR_WINDOW,
            "compromised_image_digest": incident.COMPROMISED_DIGEST,
            "summary": INCIDENT_SUMMARY,
        },
        "scan": {
            "target": result.target,
            "timestamp_utc": _timestamp(),
            "files_scanned": result.files_scanned,
        },
        "summary": {"total_findings": len(result.findings),
                    "by_severity": counts},
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity,
                "component": {
                    "name": f.component_name,
                    "type": f.component_type,
                    "vendor": "LiteLLM (BerriAI)",
                },
                "evidence": {
                    "type": f.evidence_type,
                    "source_file": f.file,
                    "line": f.line,
                    "snippet": f.snippet,
                },
                "incident_basis": f.basis,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
        "vendor_response_steps": incident.RESPONSE_STEPS,
        "limitations": LIMITATIONS,
    }


def render_json(result: ScanResult, ruleset: RuleSet) -> str:
    return json.dumps(to_json_dict(result, ruleset), indent=2,
                      ensure_ascii=False) + "\n"


def render_markdown(result: ScanResult, ruleset: RuleSet) -> str:
    counts = result.counts_by_severity()
    out: list[str] = []
    out.append("# LiteLLM v1.107.0 Exposure Check - Evidence Report")
    out.append("")
    out.append(
        "Generated by `litellm-check` "
        f"(tool v{__version__}, rules v{ruleset.rules_version})."
    )
    out.append("")
    out.append("| Field | Value |")
    out.append("|---|---|")
    out.append(f"| Scan target | `{result.target}` |")
    out.append(f"| Timestamp (UTC) | {_timestamp()} |")
    out.append(f"| Files scanned | {result.files_scanned} |")
    out.append(f"| Total findings | {len(result.findings)} |")
    out.append("")
    out.append("## Incident summary (from the vendor announcement)")
    out.append("")
    out.append(INCIDENT_SUMMARY)
    out.append("")
    out.append(
        "This report lists exposure indicators found in the scanned "
        "tree, with file-and-line evidence, so the results can be "
        "handed to an engineering or security team. Read the "
        "**Detection limits** section before drawing conclusions."
    )
    out.append("")
    out.append("## Summary by severity")
    out.append("")
    if counts:
        out.append("| Severity | Findings |")
        out.append("|---|---|")
        for sev in sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 99)):
            out.append(f"| {sev} | {counts[sev]} |")
    else:
        out.append("No findings.")
    out.append("")
    out.append("## Findings")
    out.append("")
    if not result.findings:
        out.append(
            "No indicators from the current rule set were found in the "
            "scanned tree. This is a statement about the indicators in "
            f"rules v{ruleset.rules_version} only - see **Detection "
            "limits** below for what a scan cannot rule out."
        )
        out.append("")
    else:
        current_sev = None
        for f in result.findings:
            if f.severity != current_sev:
                current_sev = f.severity
                out.append(f"### {current_sev.capitalize()}")
                out.append("")
            loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
            out.append(f"#### {f.rule_name} ({f.rule_id})")
            out.append("")
            out.append(f"- Location: {loc}")
            out.append(f"- Component: {f.component_name} ({f.component_type})")
            out.append(f"- Evidence type: {f.evidence_type}")
            out.append("")
            out.append("```")
            out.append(f.snippet)
            out.append("```")
            out.append("")
            if f.basis:
                out.append(f"Incident basis: {f.basis}")
                out.append("")
            if f.remediation:
                out.append(f"Suggested remediation: {f.remediation}")
                out.append("")
    out.append("## If you are affected - vendor response steps")
    out.append("")
    out.append(
        "Condensed from the announcement's \"What to do if you are "
        "affected\" section:"
    )
    out.append("")
    for i, step in enumerate(incident.RESPONSE_STEPS, start=1):
        out.append(f"{i}. {step}")
    out.append("")
    out.append("## Detection limits")
    out.append("")
    out.append(LIMITATIONS)
    out.append("")
    return "\n".join(out)
