# X thread — 定稿待发（2026-10-22 定稿，今晚发）

- 目标链接：https://github.com/dylanXM/litellm-check
- 账号：X @bakuraxm（网页端常驻会话发布）
- 发法：逐条按编号发成 thread，共 9 条；每条已按 X 计数规则核过 ≤280（链接按 23 字符、emoji 按 2 计）
- 发布前检查项：
  - [ ] 仓库公开页可访问、README 渲染正常、CI 绿
  - [ ] **PyPI 链接占位**：第 9 条含 PyPI 链接 https://pypi.org/project/litellm-check/ ——PyPI 发版完成、该页可打开后再发本 thread；发版未成则把第 9 条安装行换回 `pip install git+https://github.com/dylanXM/litellm-check.git` 再发
  - [ ] 全新 venv 实测安装命令可用、demo 扫描输出 16 findings
  - [ ] 红线词自查：certified / guarantee / compliant / "safe" 断言零命中

——— 以下为粘贴内容 ———

1/ LiteLLM v1.107.0 was compromised yesterday — the bad release hit PyPI, Docker Hub and GHCR before it was contained.

If litellm is anywhere in your stack, the vendor's response steps start with checks most people are doing by hand. 🧵

2/ The nasty part: in an affected environment, *any* Python start re-runs the implant. So the official steps say don't begin with pip install or pip show on a suspect box — you check files and metadata first, from the shell.

3/ I built litellm-check to automate that first pass. Zero-dependency Python CLI:

`litellm-check scan ./your-project`

Or point it at the folder where your virtualenvs live to check installed environments.

4/ It evaluates version specs instead of grepping: a pin of exactly 1.107.0 is critical. Unpinned / >= / ~= / ^ specs that admit 1.107.0 are high. Specs that exclude it are info — kept in the report so reviewers see the coverage.

5/ Also covered: lockfiles (poetry / uv / pipenv), Dockerfile + compose tags (v1.107.0, latest, main-latest) and the compromised image digest, installed litellm-*.dist-info metadata, and the implant marker files: cook.pth, cook.py, remote_code_loader.lock.

6/ Exposure windows from the official announcement:
• PyPI — Oct 21, 11:39:51–13:23 UTC
• Docker Hub — 11:46:56–14:20 UTC
• GHCR — until 13:51 UTC

Whether an "admits" finding actually installed the bad version depends on installs inside those windows.

7/ The honest limit, printed on every report: a clean scan means "none of the known indicators were found" — nothing more. Envs rebuilt after exposure, images pulled outside any definition file, CI-only installs leave nothing to find.

8/ Output is an evidence report: file:line, the matched spec/tag/file, the incident basis, and the vendor's remediation steps — rebuild pinned to litellm==1.106.2, rotate every reachable secret, check CloudTrail. Markdown or JSON; --fail-on works as a CI gate.

9/ Apache-2.0, runs fully local, reads files only — it never executes Python inside a scanned environment.

Install: pip install litellm-check
PyPI: https://pypi.org/project/litellm-check/
Repo: https://github.com/dylanXM/litellm-check

Sample report is in examples/. If your stack exposes litellm somewhere the 13 rules miss, I want the issue.
