# litellm-check

**Did the compromised LiteLLM v1.107.0 release touch your code, your images, or your Python environments?** `litellm-check` scans a source tree and/or local Python environments for the exposure surface of the 2026-10-21 LiteLLM supply-chain incident and writes an evidence report (Markdown or JSON).

Every detection rule is derived from LiteLLM's **official incident announcement** — [“Contained: Oct 21, 2026 LiteLLM release v1.107.0 Compromised”](https://docs.litellm.ai/blog/security-incident-oct-21-2026) (last updated 2026-10-21 20:30 UTC). No third-party IOC lists are used. The tool collects evidence only; **it never certifies an environment as safe** — the announcement itself warns that not finding an indicator does not prove an environment is clean.

Zero third-party dependencies. Python 3.11+. It reads files only and **never executes Python (or pip) inside a scanned environment** — which matters, because the announcement warns that any Python start in an affected environment re-runs the implant.

## Install

```bash
pip install litellm-check        # or from a checkout:
pip install .
```

## Usage

```bash
# Scan a project checkout
litellm-check scan ~/src/my-service

# Scan where your virtualenvs live (this is how you check installed envs)
litellm-check scan ~/projects --format json --out report.json

# CI gate: fail the job if any critical indicator is present
litellm-check scan . --fail-on critical

# Equivalent without installing
python -m litellm_check scan <path>
```

Exit codes: `0` = scan completed (findings are reported, not gated), `1` = a finding met the `--fail-on` threshold, `2` = usage error.

## What it scans

| Surface | Files | What is evaluated |
|---|---|---|
| Dependency manifests | `requirements*.txt`, `pyproject.toml` (PEP 621 deps, optional-deps, PEP 735 dependency-groups, Poetry), `Pipfile`, `setup.py`, `setup.cfg`, conda `environment.yml` | The version spec is **evaluated**, not grepped: does it pin exactly `1.107.0` (critical), admit it — unpinned, `>=`, `~=`, Poetry `^`/`~`, wildcards (high) — or exclude it (info) |
| Lockfiles | `poetry.lock`, `uv.lock`, `Pipfile.lock` | The resolved litellm version: `1.107.0` = critical |
| Container definitions | `Dockerfile*`, `docker-compose*.yml` | Image tags `v1.107.0` (critical) and `latest` / `main-latest` / `main-stable` / untagged (high, they pointed at the bad image during the window); the compromised image digest anywhere in any text file (critical); GHCR digests — the announcement publishes them truncated, so those are prefix-matched and labelled as such |
| Installed environments | any `litellm-*.dist-info` in the tree (e.g. under `.venv/`, `env/`, system site-packages you point it at) | This is the announcement's `pip show litellm` check, done by reading metadata: version `1.107.0` = critical, other versions = info |
| Implant & marker files | anywhere in the tree | `litellm-1.107.0.dist-info`, `cook.pth`, `cook.py`, `sitecustomize.py`, `__pycache__` implant bytecode, `remote_code_loader.lock` — the exact filenames the announcement tells you to search for and delete. Critical when inside a `site-packages` directory |

Rule IDs `LL-001` … `LL-013` with the incident basis and remediation for each live in [`rules/litellm.rules.json`](rules/litellm.rules.json) and are printed in full in every report.

## What it does not scan / cannot prove

- **A clean report is not a clean bill of health.** Environments rebuilt or deleted after exposure, images pulled without any definition file in the tree, and anything recorded only in CI logs / shell history / registry audit logs leave nothing for this tool to find.
- “Admits” findings (LL-003, LL-007) mark **exposure surface**, not proof of installation: whether an unpinned spec actually resolved to 1.107.0 depends on whether an install ran inside the announced windows (PyPI 2026-10-21 11:39:51–13:23 UTC; Docker 11:46:56–14:20 UTC; GHCR until 13:51 UTC). Pair the scan with install timestamps.
- It does not inspect running processes, network/egress logs, image layers, or host state outside the directory you point it at (e.g. point it at `/tmp` too if you want the daemon lock-file check to cover the real `/tmp`).
- It does not hash installed files: the announcement publishes no wheel hashes, so no rule is built on hashes.
- Enterprise customers on LiteLLM's private registry were **not** impacted (per the announcement); this tool checks the public artifacts only.

## How to read the report

- **Summary by severity** — counts first. `critical` = an artifact the vendor says to treat as compromised is present. `high` = exposure that depends on install/pull timing, or an implant-named file outside `site-packages`. `info` = litellm present but pinned/resolved/installed at a version that excludes 1.107.0 (kept in the report so reviewers can see coverage, per the announcement that all pre-1.107.0 versions are safe).
- **Findings** — each with file:line evidence, the exact spec/tag/file matched, the incident basis (what the announcement says about it), and a remediation.
- **Vendor response steps** — condensed from the announcement's “What to do if you are affected”: do **not** start with `pip install` (it re-executes the implant); delete the implant files from the shell; kill the daemon holding `/tmp/remote_code_loader.lock`; rebuild pinned to `litellm==1.106.2`; rotate every secret the host could reach; check CloudTrail.
- **Detection limits** — the full statement above, printed in every report.

## Demo

[`examples/demo-project/`](examples/demo-project) is a deliberately exposed sample project (affected pin, floating tag, digest-pinned compose service, a fake `.venv` with inert stand-ins for the implant files). Its generated report is committed:

```bash
litellm-check scan examples/demo-project
# 16 findings: 10 critical, 4 high, 2 info — see examples/sample-report.md
```

## Development

```bash
pip install -e ".[dev]"
pytest -q          # 58 tests
ruff check src tests
```

Layout mirrors the rules-as-data design: rule metadata in `rules/litellm.rules.json` (a byte-identical copy is bundled in the package; a test keeps them in sync), incident facts in `src/litellm_check/incident.py`, spec evaluation in `specs.py`, detectors in `scanner.py`.

## License

Apache-2.0. Not affiliated with BerriAI/LiteLLM; “LiteLLM” is used only to name the incident this tool audits.
