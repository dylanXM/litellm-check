# Repository setup checklist (run once, at repo creation)

## Name

- **`litellm-check`** — `github.com/dylanXM/litellm-check` (matches the PyPI
  package name and the CLI command; no fallback needed unless taken)

## About (right-hand sidebar)

Description (one line):

> One-command self-audit for the compromised LiteLLM v1.107.0 release: scan your code, lockfiles, container definitions and Python environments against the indicators in LiteLLM's official incident announcement, and get an evidence report.

Website: leave blank until a landing page exists (do not link the repo itself).

## Topics (GitHub allows up to 20)

```
litellm
supply-chain-security
security-scanner
incident-response
ioc
devsecops
python
cli
docker
pypi
llm
ai-security
static-analysis
```

## Social preview (Settings → Social preview, 1280×640)

Text for the preview image:

> **litellm-check**
> Were you exposed to LiteLLM v1.107.0?
> One scan. Evidence report. Limits printed on the report.

Suggested image: dark background, terminal-style excerpt of
`examples/sample-report.md` (severity summary + one critical finding),
project name large at top-left. Do not use the LiteLLM/BerriAI logo.

## One-time settings

- [ ] Create the repo **public and empty** (no README / .gitignore /
      license — all already in the first commit)
- [ ] Add the deploy key (public half: `~/.ssh/litellm_check_deploy.pub`,
      fingerprint `SHA256:0soHjQKKQNAnNfj4E5R/RA6ENZrLJwOEXASzkw3j74I`),
      title it `litellm-check deploy (local build machine)`, **allow write
      access**
- [ ] Actions: enabled (CI workflow already in repo)
- [ ] Default branch: `main`
- [ ] Releases: create `v0.1.0` after the first push; attach
      `examples/sample-report.md` and `examples/sample-report.json`
- [ ] Issues: enable; Discussions: optional
- [ ] Pin nothing yet; add to the profile's pinned list only after the
      launch posts go out
