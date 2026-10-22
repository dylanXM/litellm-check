# Remediation checklist — LiteLLM v1.107.0 incident

A checkable version of the response steps in LiteLLM's official incident
announcement, “Contained: Oct 21, 2026 LiteLLM release v1.107.0 Compromised”
(<https://docs.litellm.ai/blog/security-incident-oct-21-2026>, updated
2026-10-21 20:30 UTC). Work through it per host / environment. If you find a
critical indicator at any step, treat the environment as compromised and
complete every remaining step — do not stop at “removed the package.”

## 0. Establish exposure

- [ ] Run `litellm-check scan <path>` over your repos **and** the folders
      holding your Python environments; save the report
- [ ] Check install / pull timestamps against the announced windows:
      PyPI **2026-10-21 11:39:51–13:23 UTC** · Docker Hub
      **11:46:56–14:20 UTC** · GHCR until **13:51 UTC**
- [ ] Note which environments installed or pulled anything inside those
      windows (unpinned / floating specs and tags included)

## 1. Do not execute the implant

- [ ] Do **not** run `pip install`, `pip show`, or start Python inside a
      suspect environment — any Python start re-runs the implant
- [ ] Do all inspection from the shell, on files and metadata only

## 2. Remove the implant files (from the shell)

- [ ] Delete `cook.pth` and `cook.py` from every affected `site-packages`
- [ ] Delete any planted `sitecustomize.py` and the implant bytecode under
      `__pycache__` named in the announcement
- [ ] Delete the `litellm-1.107.0.dist-info` directory
- [ ] Delete `/tmp/remote_code_loader.lock`

## 3. Stop the daemon

- [ ] Find and kill the process holding `/tmp/remote_code_loader.lock`
      (e.g. `lsof /tmp/remote_code_loader.lock`)
- [ ] Confirm the lock file is not recreated

## 4. Rebuild clean

- [ ] Rebuild the environment / image from a clean base — do not “repair”
      the compromised one in place
- [ ] Pin the last unaffected release: `litellm==1.106.2`
- [ ] Remove or re-pin any floating spec/tag that admitted 1.107.0
      (`latest`, `main-latest`, unpinned requirements, `^`/`~=` ranges)

## 5. Rotate secrets

- [ ] Rotate **every** secret the host or environment could reach:
      LiteLLM / provider API keys, cloud credentials, database passwords,
      service tokens, session secrets
- [ ] Revoke sessions issued during the exposure window where your
      providers support it

## 6. Audit for misuse

- [ ] Review AWS CloudTrail (or your cloud's equivalent audit log) for
      suspicious activity from the exposure window onward
- [ ] Review outbound network / egress logs for unknown destinations
- [ ] Check for persistence you did not create: new users, keys, cron
      entries, systemd units, startup scripts

## 7. Close out

- [ ] Re-run `litellm-check scan` on the rebuilt environment and file the
      new report next to the original
- [ ] Record what was exposed, what was rotated, and the rebuild date for
      your incident file / customer notifications

*Caveats: a clean scan means none of the known indicators were found — it
is not proof an environment is clean. Environments rebuilt or deleted
after exposure, and pulls recorded only in CI or registry logs, leave
nothing on disk to find. Per the announcement, enterprise customers on
LiteLLM's private registry were not impacted.*
