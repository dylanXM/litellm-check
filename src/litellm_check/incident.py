"""Incident facts, transcribed from LiteLLM's official announcement.

Source: "Contained: Oct 21, 2026 LiteLLM release v1.107.0 Compromised"
https://docs.litellm.ai/blog/security-incident-oct-21-2026
(last updated 2026-10-21 20:30 UTC; read 2026-10-22).

Only facts stated in that announcement live here. Third-party write-ups
mention additional indicators (file hashes, extra marker files, C2
endpoints); they are deliberately NOT used, because the announcement -
the vendor's own account - is the sole basis for this tool's rules.
"""

from __future__ import annotations

SOURCE_URL = "https://docs.litellm.ai/blog/security-incident-oct-21-2026"
SOURCE_TITLE = "LiteLLM incident announcement: Oct 21, 2026 LiteLLM release v1.107.0 Compromised"
SOURCE_UPDATED = "2026-10-21 20:30 UTC"

PACKAGE = "litellm"
AFFECTED_VERSION = "1.107.0"
AFFECTED_VERSION_TUPLE = (1, 107, 0)
# "For the time being, please pin your version to 1.106.2 or any explicit
# version published prior to now." / "All previous versions are safe."
RECOMMENDED_PIN = "1.106.2"

# Exposure windows (UTC, 2026-10-21), per the announcement.
PYPI_WINDOW = "2026-10-21 11:39:51-13:23 UTC"
DOCKER_WINDOW = "2026-10-21 11:46:56-14:20 UTC"
GHCR_WINDOW = "2026-10-21 11:46:56-13:51 UTC"

# Compromised image index (Docker Hub tags v1.107.0, latest, main-latest,
# main-stable pointed at it). The announcement gives this digest in full.
COMPROMISED_DIGEST = (
    "sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e"
)

# GHCR repositories named in the announcement. The announcement publishes
# their digests TRUNCATED (shown with an ellipsis); only the prefix is
# recorded here and prefix matching is labelled as such in findings.
GHCR_REPOS = {
    "ghcr.io/berriai/litellm": "sha256:1bbcb1443bc9",
    "ghcr.io/berriai/litellm-database": "sha256:c00f9d92c427",
    "ghcr.io/berriai/litellm-non_root": "sha256:7b00e91cd2fe",
}

# Image repositories in scope: the announcement names the GHCR paths
# explicitly and lists the same tags for Docker Hub, whose repository is
# berriai/litellm (and the -database / -non_root variants).
IMAGE_REPOS = {
    "berriai/litellm",
    "berriai/litellm-database",
    "berriai/litellm-non_root",
    *GHCR_REPOS.keys(),
}

AFFECTED_TAG = "v1.107.0"
FLOATING_TAGS = {"latest", "main-latest", "main-stable"}

# Filesystem evidence named in the announcement.
# - "Search filesystem evidence for litellm-1.107.0.dist-info, cook.pth,
#    and sitecustomize.py."
# - Response step 1 adds cook.py and __pycache__/cook*.pyc /
#   sitecustomize*.pyc.
# - Response step 2: the detached daemon holds /tmp/remote_code_loader.lock;
#   step 4: "If the marker file exists, the exfil is confirmed."
IMPLANT_FILES_EXACT = {"cook.pth", "cook.py"}
SITECUSTOMIZE_FILE = "sitecustomize.py"
DAEMON_MARKER_FILE = "remote_code_loader.lock"

# The announcement's own response steps, condensed for the report.
RESPONSE_STEPS = [
    "Do NOT start with pip install: any Python start in an affected environment runs cook.pth and sitecustomize.py again, and that includes running pip.",
    "From the shell, delete cook.pth, cook.py, sitecustomize.py and any matching __pycache__/cook*.pyc and sitecustomize*.pyc from every affected site-packages.",
    "Kill the detached python daemon (it holds /tmp/remote_code_loader.lock).",
    "Reinstall pinned to litellm==1.106.2. Rebuilding images and venvs from scratch is better.",
    "If 1.107.0 was ever installed on a host with outbound internet, assume the exfiltration succeeded; rotate everything the host could reach: the instance/task IAM role, every provider key stored in the LiteLLM proxy DB plus the master and virtual keys, the DATABASE_URL password, and any secret in the environment of any process on the host.",
    "Check CloudTrail for GetCallerIdentity from the instance role around install time, then for use of the role's credentials from outside your infrastructure.",
]
