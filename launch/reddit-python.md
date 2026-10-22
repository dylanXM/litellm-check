# r/Python — 定稿待发（2026-10-22 定稿，今晚发）

- 目标链接：https://github.com/dylanXM/litellm-check
- 板块选择：主发 **r/Python**（工具本体是 Python CLI，受众即 LiteLLM 的主要用户群）。r/devops 的自推管控更严，不在同一天跨发；如要扩散，隔日单独评估或走其允许的自推帖
- 板块规则合规点：正文第一人称写明「I built this」（作者披露）；不刷帖、不跨板块同日同链；发后守在帖下答疑，不另开新帖引流
- 发布前检查项：
  - [ ] 仓库公开页可访问、README 渲染正常、CI 绿
  - [ ] 全新 venv 实测安装 + `litellm-check scan examples/demo-project` 输出 16 findings（10 critical / 4 high / 2 info）
  - [ ] PyPI 发版完成后，把正文安装命令换成 `pip install litellm-check`（发版前保留 git+https 形式）
  - [ ] 红线词自查：certified / guarantee / compliant / "safe" 断言零命中；口径只讲「自查 + 证据报告」

——— 以下为粘贴内容 ———

**Title:**
I built litellm-check: a one-command audit for whether the compromised LiteLLM v1.107.0 touched your code, images, or virtualenvs

**Body:**

Yesterday (Oct 21) LiteLLM disclosed that v1.107.0 was compromised and pushed to PyPI, Docker Hub, and GHCR before being contained. Official announcement: https://docs.litellm.ai/blog/security-incident-oct-21-2026

The response steps in that announcement are all manual file/metadata checks — and one of them is counterintuitive: in an affected environment, *any* Python start re-runs the implant, so you're told not to start with `pip install` / `pip show` on a suspect box. I kept seeing people ask "how do I know if I was exposed?" in issue threads, so I turned the announcement's checks into a small CLI:

```
pip install git+https://github.com/dylanXM/litellm-check.git
litellm-check scan ./your-project
```

Point it at a repo to check the code side, or at the folder where your virtualenvs live to check installed environments.

**What it checks (13 rules, each derived from the announcement)**

- Dependency manifests — the version spec is *evaluated*, not grepped: exactly `1.107.0` = critical; a spec that admits it (unpinned, `>=`, `~=`, Poetry `^`/`~`, wildcards) = high; a spec that excludes it = info, kept in the report so reviewers see the coverage
- Lockfiles (`poetry.lock`, `uv.lock`, `Pipfile.lock`): resolved version `1.107.0` = critical
- Dockerfiles / compose: tags `v1.107.0` (critical), `latest` / `main-latest` / untagged (high — they pointed at the bad image during the window), plus the compromised image digest
- Installed environments: `litellm-*.dist-info` metadata — the announcement's `pip show litellm` check done by reading files, without starting Python
- Implant marker files: `cook.pth`, `cook.py`, planted `sitecustomize.py`, `remote_code_loader.lock`

Exposure windows from the announcement, for judging "admits" findings: PyPI Oct 21 11:39:51–13:23 UTC, Docker 11:46:56–14:20 UTC, GHCR until 13:51 UTC.

Output is a Markdown or JSON evidence report (file:line, matched spec/tag, the announcement basis, remediation). `--fail-on critical` works as a CI gate. Zero third-party dependencies, Python 3.11+, Apache-2.0. The demo project under `examples/` is deliberately exposed; its report (16 findings) is committed if you want to see the output shape first.

**Limits, up front**

A clean scan means "none of the known indicators were found" — nothing more, and the report prints exactly that. Environments rebuilt after exposure, images pulled without a definition file in the tree, or CI-only installs leave nothing on disk to find. This is evidence collection, not a safety certification.

Repo: https://github.com/dylanXM/litellm-check — rule PRs with fixtures are the most useful contribution if your stack exposes LiteLLM somewhere the current 13 rules miss.

Not affiliated with BerriAI/LiteLLM; "LiteLLM" is used only to name the incident this tool audits.
