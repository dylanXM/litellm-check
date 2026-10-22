"""Scanner: walks a tree and evaluates LiteLLM exposure surface.

Detection surfaces (all derived from the incident announcement):

- dependency manifests: requirements*.txt, pyproject.toml (PEP 621,
  PEP 735 dependency-groups, Poetry), Pipfile, setup.py, setup.cfg,
  conda environment.yml - version specs are *evaluated* against the
  affected release (pinned vs admits vs excludes), not just grepped;
- lockfiles: poetry.lock, uv.lock, Pipfile.lock - the resolved version;
- container definitions: Dockerfile*, docker-compose*.yml - image
  tags and digests named in the announcement;
- installed environments: litellm-*.dist-info metadata anywhere in
  the tree (this is the `pip show litellm` check from the
  announcement, done by reading files, never by executing Python in
  the scanned environment);
- implant/marker files the announcement names: cook.pth, cook.py,
  sitecustomize.py, __pycache__ implant bytecode,
  remote_code_loader.lock.

Detection is evidence of presence only - see LIMITATIONS in the
reports. Nothing in the scanned tree is executed.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from . import incident, specs
from .rules import RuleSet

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Only VCS internals and node_modules are skipped. In particular
# .venv / venv / __pycache__ are NOT skipped: installed-environment
# evidence and implant files live there.
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules"}
MAX_TEXT_BYTES = 5 * 1024 * 1024
MAX_SNIPPET = 200

_SECRET_RE = re.compile(r"(sk-[A-Za-z0-9_\-]{6,}|ghp_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{12,})")

_DIST_INFO_RE = re.compile(r"^litellm-(.+)\.dist-info$", re.IGNORECASE)
_IMAGE_RE = re.compile(
    r"(?P<repo>(?:ghcr\.io/)?berriai/(?:litellm-database|litellm-non_root|litellm))"
    r"(?::(?P<tag>[A-Za-z0-9_.\-]+))?"
    r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?"
)
_NAME_SPEC_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*(.*)$")
_PIP_INSTALL_RE = re.compile(r"\b(?:pip3?|uv\s+pip)\s+install\b")


def _redact(text: str) -> str:
    return _SECRET_RE.sub(lambda m: m.group(0)[:3] + "-***REDACTED***", text)


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    evidence_type: str
    component_type: str
    component_name: str
    file: str  # path relative to scan root, posix separators
    line: int | None
    snippet: str
    basis: str
    remediation: str

    def key(self) -> tuple:
        return (self.rule_id, self.file, self.line, self.snippet)


@dataclass
class ScanResult:
    target: str
    files_scanned: int
    findings: list[Finding]

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def _line_of(lines: list[str], needle: str, start: int = 0) -> int | None:
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    return None


def _logical_lines(lines: list[str]):
    """Yield (start_lineno, text) joining backslash continuations."""
    buf: str | None = None
    start = 0
    for i, raw in enumerate(lines, start=1):
        if buf is None:
            buf, start = raw, i
        else:
            buf += raw
        stripped = buf.rstrip()
        if stripped.endswith("\\"):
            buf = stripped[:-1] + " "
            continue
        yield start, buf
        buf = None
    if buf is not None:
        yield start, buf


class _Scan:
    def __init__(self, root: Path, ruleset: RuleSet):
        self.root = root
        self.ruleset = ruleset
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()
        self.files_scanned = 0

    # ------------------------------------------------------------ core
    def add(self, rule_id: str, *, file: str, line: int | None,
            snippet: str, component_name: str,
            severity: str | None = None) -> None:
        rule = self.ruleset.by_id(rule_id)
        finding = Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=severity or rule.severity,
            evidence_type=rule.evidence_type,
            component_type=rule.component_type,
            component_name=component_name,
            file=file,
            line=line,
            snippet=_redact(snippet.strip())[:MAX_SNIPPET],
            basis=rule.basis,
            remediation=rule.remediation,
        )
        k = finding.key()
        if k not in self._seen:
            self._seen.add(k)
            self.findings.append(finding)

    def spec_verdict(self, pins: bool, admits: bool, *, file: str,
                     line: int | None, snippet: str,
                     component_name: str) -> None:
        if pins:
            self.add("LL-001", file=file, line=line, snippet=snippet,
                     component_name=component_name)
        elif admits:
            self.add("LL-003", file=file, line=line, snippet=snippet,
                     component_name=component_name)
        else:
            self.add("LL-004", file=file, line=line, snippet=snippet,
                     component_name=component_name)

    def lock_verdict(self, version: str, *, file: str, line: int | None,
                     snippet: str) -> None:
        parsed = specs.parse_version(version)
        if parsed is not None and parsed == incident.AFFECTED_VERSION_TUPLE:
            self.add("LL-002", file=file, line=line, snippet=snippet,
                     component_name=f"litellm {version} (locked)")
        else:
            self.add("LL-004", file=file, line=line, snippet=snippet,
                     component_name=f"litellm {version} (locked)")

    # ------------------------------------------------- dependency specs
    def dep_string(self, text: str, *, file: str, line: int | None,
                   snippet: str | None = None) -> None:
        """Evaluate one PEP 508-style dependency string."""
        body = text.strip().split(";")[0].strip()
        m = _NAME_SPEC_RE.match(body)
        if not m or _normalize_name(m.group(1)) != incident.PACKAGE:
            return
        rest = (m.group(3) or "").strip()
        component = ("litellm" + (m.group(2) or "") +
                     (f" {rest}" if rest else ""))
        snippet = snippet if snippet is not None else text.strip()
        if rest.startswith("@"):
            url = rest[1:].strip()
            vm = re.search(r"litellm[-_](\d+\.\d+(?:\.\d+)?)", url, re.IGNORECASE)
            if vm:
                version = specs.parse_version(vm.group(1))
                if version == incident.AFFECTED_VERSION_TUPLE:
                    self.add("LL-001", file=file, line=line, snippet=snippet,
                             component_name=component)
                else:
                    self.add("LL-004", file=file, line=line, snippet=snippet,
                             component_name=component)
            elif incident.AFFECTED_VERSION in url:
                self.add("LL-001", file=file, line=line, snippet=snippet,
                         component_name=component)
            else:
                self.add("LL-003", file=file, line=line, snippet=snippet,
                         component_name=component)
            return
        pins, admits = specs.evaluate_pep440(rest)
        self.spec_verdict(pins, admits, file=file, line=line,
                          snippet=snippet, component_name=component)

    def parse_requirements(self, lines: list[str], rel: str) -> None:
        for lineno, raw in _logical_lines(lines):
            line = re.sub(r"\s+#.*$", "", raw).strip()
            if not line or line.startswith("#"):
                continue
            if "litellm" not in line.lower():
                continue
            if line.startswith("-"):
                if incident.AFFECTED_VERSION in line:
                    self.add("LL-001", file=rel, line=lineno, snippet=line,
                             component_name="litellm (direct reference)")
                continue
            self.dep_string(line, file=rel, line=lineno)

    def parse_setup_py(self, lines: list[str], rel: str) -> None:
        in_requires = False
        for lineno, raw in enumerate(lines, start=1):
            if re.search(r"(install_requires|setup_requires|tests_require)",
                         raw):
                in_requires = True
            for sm in re.finditer(r"([\"'])(.*?)\1", raw):
                s = sm.group(2).strip()
                if not re.match(r"(?i)litellm(?![\w.\-])", s):
                    continue
                has_ops = bool(re.search(r"[<>=!~@]", s))
                if has_ops or in_requires:
                    self.dep_string(s, file=rel, line=lineno, snippet=raw)

    def parse_pyproject(self, text: str, lines: list[str], rel: str) -> None:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return
        project = data.get("project", {}) or {}
        dep_lists: list[str] = []
        dep_lists += project.get("dependencies", []) or []
        for extra in (project.get("optional-dependencies", {}) or {}).values():
            dep_lists += extra or []
        for group in (data.get("dependency-groups", {}) or {}).values():
            if isinstance(group, list):
                dep_lists += [g for g in group if isinstance(g, str)]
        for dep in dep_lists:
            if isinstance(dep, str) and "litellm" in dep.lower():
                line = _line_of(lines, dep) or _line_of(lines, "litellm")
                self.dep_string(dep, file=rel, line=line)
        poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
        dep_dicts: list[dict] = []
        if isinstance(poetry.get("dependencies"), dict):
            dep_dicts.append(poetry["dependencies"])
        for group in (poetry.get("group", {}) or {}).values():
            if isinstance(group, dict) and isinstance(
                    group.get("dependencies"), dict):
                dep_dicts.append(group["dependencies"])
        poetry_start = 0
        for i, raw_line in enumerate(lines):
            if "tool.poetry" in raw_line:
                poetry_start = i
                break
        for dep_dict in dep_dicts:
            for name, value in dep_dict.items():
                if _normalize_name(name) != incident.PACKAGE:
                    continue
                if isinstance(value, dict):
                    constraint = str(value.get("version", ""))
                else:
                    constraint = str(value)
                pins, admits = specs.evaluate_poetry(constraint)
                line = _line_of(lines, "litellm", start=poetry_start)
                self.spec_verdict(
                    pins, admits, file=rel, line=line,
                    snippet=f' litellm = "{constraint}" '.strip(),
                    component_name=f"litellm {constraint}".strip())

    def parse_lock_toml(self, text: str, lines: list[str], rel: str) -> None:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return
        for pkg in data.get("package", []) or []:
            if not isinstance(pkg, dict):
                continue
            if _normalize_name(str(pkg.get("name", ""))) != incident.PACKAGE:
                continue
            version = str(pkg.get("version", ""))
            name_line = _line_of(lines, 'name = "litellm"') or \
                _line_of(lines, "name = 'litellm'")
            line = None
            if name_line:
                vline = _line_of(lines, "version =", start=name_line - 1)
                line = vline or name_line
            self.lock_verdict(version, file=rel, line=line,
                              snippet=f'name = "litellm", version = "{version}"')

    def parse_pipfile(self, text: str, lines: list[str], rel: str) -> None:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return
        for section in ("packages", "dev-packages"):
            entries = data.get(section, {}) or {}
            if not isinstance(entries, dict):
                continue
            for name, value in entries.items():
                if _normalize_name(name) != incident.PACKAGE:
                    continue
                if isinstance(value, dict):
                    constraint = str(value.get("version", ""))
                else:
                    constraint = str(value)
                pins, admits = specs.evaluate_poetry(constraint)
                line = _line_of(lines, "litellm")
                self.spec_verdict(
                    pins, admits, file=rel, line=line,
                    snippet=f' litellm = "{constraint}" '.strip(),
                    component_name=f"litellm {constraint}".strip())

    def parse_pipfile_lock(self, text: str, lines: list[str], rel: str) -> None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        for section in ("default", "develop"):
            entries = data.get(section, {}) or {}
            if not isinstance(entries, dict):
                continue
            for name, info in entries.items():
                if _normalize_name(name) != incident.PACKAGE:
                    continue
                raw = str((info or {}).get("version", ""))
                version = raw.lstrip("=").strip()
                key_line = _line_of(lines, '"litellm"')
                line = key_line
                if key_line:
                    line = _line_of(lines, '"version"', start=key_line - 1) \
                        or key_line
                self.lock_verdict(version, file=rel, line=line,
                                  snippet=f'"litellm": "version": "{raw}"')

    def parse_conda_env(self, lines: list[str], rel: str) -> None:
        in_pip = False
        pip_indent = -1
        for lineno, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip())
            if re.match(r"^-\s*pip:\s*$", stripped):
                in_pip, pip_indent = True, indent
                continue
            if stripped.startswith("- "):
                item = stripped[2:].strip().strip("'\"")
                if in_pip and indent <= pip_indent:
                    in_pip = False
                if "litellm" not in item.lower():
                    continue
                if in_pip:
                    self.dep_string(item, file=rel, line=lineno,
                                    snippet=raw)
                    continue
                body = item.rsplit("::", 1)[-1]  # strip channel prefix
                m = re.match(r"(?i)litellm(?![\w.\-])\s*(.*)$", body)
                if not m:
                    continue
                spec = (m.group(1) or "").strip()
                pins, admits = specs.evaluate_conda(spec)
                self.spec_verdict(pins, admits, file=rel, line=lineno,
                                  snippet=raw,
                                  component_name=f"litellm {spec}".strip())
            elif indent == 0:
                in_pip = False

    # ------------------------------------------------------- containers
    def image_verdict(self, repo: str, tag: str | None,
                      digest: str | None, *, file: str,
                      line: int | None, snippet: str) -> None:
        ref = repo + (f":{tag}" if tag else "") + \
            (f"@{digest}" if digest else "")
        if digest:
            if digest == incident.COMPROMISED_DIGEST:
                self.add("LL-005", file=file, line=line, snippet=snippet,
                         component_name=ref)
            elif repo in incident.GHCR_REPOS and digest.startswith(
                    incident.GHCR_REPOS[repo]):
                self.add(
                    "LL-005", file=file, line=line, snippet=snippet,
                    component_name=ref + " (GHCR digest prefix match - the "
                    "announcement publishes GHCR digests truncated)")
            # Pinned to a different digest: not an announced indicator.
            return
        if tag == incident.AFFECTED_TAG:
            self.add("LL-006", file=file, line=line, snippet=snippet,
                     component_name=ref)
        elif tag is None or tag in incident.FLOATING_TAGS or \
                tag == incident.AFFECTED_VERSION:
            self.add("LL-007", file=file, line=line, snippet=snippet,
                     component_name=ref)

    def parse_dockerfile(self, lines: list[str], rel: str) -> None:
        for lineno, raw in _logical_lines(lines):
            if raw.strip().startswith("#"):
                continue
            for m in _IMAGE_RE.finditer(raw):
                self.image_verdict(m.group("repo"), m.group("tag"),
                                    m.group("digest"), file=rel,
                                    line=lineno, snippet=raw)
            if _PIP_INSTALL_RE.search(raw):
                for token in raw.split():
                    token = token.strip("'\"").rstrip(";&\\")
                    if token.lower().startswith("litellm"):
                        self.dep_string(token, file=rel, line=lineno,
                                        snippet=raw)

    def parse_compose(self, lines: list[str], rel: str) -> None:
        for lineno, raw in enumerate(lines, start=1):
            m = re.match(r"^\s*image:\s*(\S+)\s*$", raw)
            if not m:
                continue
            value = m.group(1).strip("'\"")
            im = _IMAGE_RE.search(value)
            if im:
                self.image_verdict(im.group("repo"), im.group("tag"),
                                   im.group("digest"), file=rel,
                                   line=lineno, snippet=raw)

    # ------------------------------------------- installed environments
    def check_dist_info(self, rel_dir: str, version: str) -> None:
        parsed = specs.parse_version(version)
        if parsed == incident.AFFECTED_VERSION_TUPLE:
            self.add("LL-008", file=rel_dir, line=None,
                     snippet=f"installed distribution metadata directory "
                             f"'litellm-{version}.dist-info'",
                     component_name=f"litellm {version} (installed)")
        else:
            self.add("LL-013", file=rel_dir, line=None,
                     snippet=f"installed distribution metadata directory "
                             f"'litellm-{version}.dist-info'",
                     component_name=f"litellm {version} (installed)")

    def check_ioc_filename(self, rel: str, name: str) -> None:
        parts = rel.split("/")
        in_sp = "site-packages" in parts

        def sev(rule_id: str) -> str | None:
            rule = self.ruleset.by_id(rule_id)
            if in_sp and rule.severity_in_site_packages:
                return rule.severity_in_site_packages
            return None

        if name in incident.IMPLANT_FILES_EXACT:
            self.add("LL-009", file=rel, line=None,
                     snippet=f"implant file named '{name}'"
                             + (" in site-packages" if in_sp else ""),
                     component_name=name, severity=sev("LL-009"))
        elif name == incident.SITECUSTOMIZE_FILE:
            self.add("LL-010", file=rel, line=None,
                     snippet=f"implant file named '{name}'"
                             + (" in site-packages" if in_sp else ""),
                     component_name=name, severity=sev("LL-010"))
        elif "__pycache__" in parts and name.endswith(".pyc") and (
                name.startswith(("cook", "sitecustomize"))):
            self.add("LL-011", file=rel, line=None,
                     snippet=f"compiled implant cache named '{name}'"
                             + (" in site-packages" if in_sp else ""),
                     component_name=name, severity=sev("LL-011"))
        elif name == incident.DAEMON_MARKER_FILE:
            self.add("LL-012", file=rel, line=None,
                     snippet=f"daemon marker file named '{name}'",
                     component_name=name)

    # ------------------------------------------------------------ files
    def scan_text_file(self, fpath: Path, rel: str, name: str,
                       lines: list[str], text: str) -> None:
        # The compromised image digest is a global indicator: it can
        # appear in any text file (compose, k8s manifests, notes).
        for lineno, raw in enumerate(lines, start=1):
            if incident.COMPROMISED_DIGEST in raw:
                self.add("LL-005", file=rel, line=lineno, snippet=raw,
                         component_name="litellm image index "
                                        "(sha256:1bbcb144...)")
        lower = name.lower()
        parent = Path(rel).parent.name
        if name in ("poetry.lock", "uv.lock"):
            self.parse_lock_toml(text, lines, rel)
        elif name == "Pipfile.lock":
            self.parse_pipfile_lock(text, lines, rel)
        elif name == "Pipfile":
            self.parse_pipfile(text, lines, rel)
        elif name == "pyproject.toml":
            self.parse_pyproject(text, lines, rel)
        elif fnmatch.fnmatch(name, "requirements*.txt") or (
                parent == "requirements" and lower.endswith(".txt")):
            self.parse_requirements(lines, rel)
        elif name == "setup.py":
            self.parse_setup_py(lines, rel)
        elif name == "setup.cfg":
            self.parse_requirements(lines, rel)
        elif fnmatch.fnmatch(name, "Dockerfile*"):
            self.parse_dockerfile(lines, rel)
        elif fnmatch.fnmatch(lower, "docker-compose*.yml") or \
                fnmatch.fnmatch(lower, "docker-compose*.yaml") or \
                fnmatch.fnmatch(lower, "compose*.yml") or \
                fnmatch.fnmatch(lower, "compose*.yaml"):
            self.parse_compose(lines, rel)
        elif lower in ("environment.yml", "environment.yaml") or \
                fnmatch.fnmatch(lower, "environment*.yml") or \
                fnmatch.fnmatch(lower, "environment*.yaml"):
            self.parse_conda_env(lines, rel)


def _looks_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def scan_path(root: Path, ruleset: RuleSet) -> ScanResult:
    root = root.resolve()
    scan = _Scan(root, ruleset)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        base = Path(dirpath)
        for d in dirnames:
            m = _DIST_INFO_RE.match(d)
            if m:
                rel_dir = (base / d).relative_to(root).as_posix()
                scan.check_dist_info(rel_dir, m.group(1))
        for name in sorted(filenames):
            fpath = base / name
            rel = fpath.relative_to(root).as_posix()
            scan.check_ioc_filename(rel, name)
            try:
                size = fpath.stat().st_size
            except OSError:
                continue
            if size > MAX_TEXT_BYTES:
                continue
            try:
                raw = fpath.read_bytes()
            except OSError:
                continue
            if _looks_binary(raw[:8192]):
                continue
            text = raw.decode("utf-8", errors="replace")
            scan.files_scanned += 1
            scan.scan_text_file(fpath, rel, name, text.splitlines(), text)

    scan.findings.sort(key=lambda f: (
        SEVERITY_ORDER.get(f.severity, 99), f.file, f.line or 0, f.rule_id,
    ))
    return ScanResult(target=str(root), files_scanned=scan.files_scanned,
                      findings=scan.findings)
