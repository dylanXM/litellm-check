# Show HN — 定稿待发（2026-10-22 定稿，今晚发）

- 目标链接：https://github.com/dylanXM/litellm-check
- 账号：HN yangxm
- 提交方式：Title 栏填标题、URL 栏填仓库地址；提交后立刻把下面正文贴为第一条作者评论（HN 的 URL 帖正文走首评）
- 建议窗口：事件热度以小时计，仓库上线后尽快；美东上午（北京晚间）为 HN 流量高峰
- 发布前检查项：
  - [ ] 仓库公开页可访问、README 渲染正常、CI 绿
  - [ ] 全新 venv 实测 `pip install git+https://github.com/dylanXM/litellm-check.git` + `litellm-check scan examples/demo-project` 输出 16 findings（10 critical / 4 high / 2 info）
  - [ ] PyPI 发版完成后，把首评里的安装命令换成 `pip install litellm-check`
  - [ ] 红线词自查：certified / guarantee / compliant / "safe" 断言零命中；口径只讲「自查 + 证据报告」

——— 以下为粘贴内容 ———

**Title:**
Show HN: litellm-check – were you exposed to the compromised LiteLLM v1.107.0?

**URL:**
https://github.com/dylanXM/litellm-check

**First comment (post immediately after submitting):**

Yesterday (Oct 21) LiteLLM disclosed that release v1.107.0 was compromised and published to PyPI, Docker Hub, and GHCR before being contained. Official announcement: https://docs.litellm.ai/blog/security-incident-oct-21-2026

The awkward part of the response steps: in an affected environment, any Python start re-runs the implant, so you are told *not* to begin with `pip install` or `pip show` on a suspect box — the checks are file and metadata checks, done manually, across requirements files, lockfiles, Dockerfiles, installed dist-info, and a handful of marker files (`cook.pth`, `remote_code_loader.lock`, …).

I automated that first pass:

`pip install git+https://github.com/dylanXM/litellm-check.git`

- Zero-dependency Python CLI: `litellm-check scan ./your-project` (point it at the folder holding your virtualenvs to check installed environments)
- Version specs are *evaluated*, not grepped: exactly `1.107.0` = critical; a spec that admits it (unpinned, `>=`, `~=`, Poetry `^`) = high; a spec that excludes it = info, kept in the report so reviewers can see coverage
- Lockfiles, Dockerfile/compose tags and the compromised image digest, installed `litellm-*.dist-info` metadata, implant marker files — 13 rules, each citing the announcement passage it comes from
- It reads files only and **never executes Python inside a scanned environment** — by design, for the reason above
- Markdown or JSON evidence report; `--fail-on critical` works as a CI gate

The limits are printed on every report: a clean scan means "none of the known indicators were found," nothing more. Environments rebuilt after exposure, images pulled without a definition file in the tree, or installs that only happened in CI leave nothing for it to find. It does not certify anything as safe.

Demo: `examples/demo-project` is a deliberately exposed sample; its report is committed (16 findings: 10 critical, 4 high, 2 info).

Feedback I would especially value: manifest formats or hiding places the rules miss, and false positives — the fixtures under tests/fixtures/ show exactly what each rule fires on.
