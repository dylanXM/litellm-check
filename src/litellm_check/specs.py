"""Version-specifier evaluation, stdlib only.

Answers exactly two questions about a dependency spec, relative to the
affected release (1.107.0):

- ``pins``:   the spec pins *exactly* the affected version
              (``==1.107.0``, poetry ``1.107.0``, conda ``=1.107.0``).
- ``admits``: the spec allows a resolver to select the affected
              version (unpinned, ``>=``, ``~=``, ``^``, ranges,
              wildcards ...). Per the incident announcement, an
              unpinned install performed on 2026-10-21 between 11:39
              and 13:23 UTC would have resolved to the malicious
              release, so "admits" is the exposure question.

Dialects: PEP 440 (requirements.txt, pyproject [project], Pipfile
values, setup.py/cfg), Poetry constraints (pyproject [tool.poetry],
Pipfile), and conda matchspecs (environment.yml). This is a pragmatic
subset: anything unparsable is treated as admitting (flag rather than
miss) and never as pinning.
"""

from __future__ import annotations

import re

from .incident import AFFECTED_VERSION_TUPLE as TARGET

_VERSION_RE = re.compile(r"^\s*v?(\d+(?:\.\d+)*)", re.IGNORECASE)


def parse_version(text: str) -> tuple[int, ...] | None:
    """Parse the dotted-numeric head of a version string."""
    if text is None:
        return None
    m = _VERSION_RE.match(str(text).strip())
    if not m:
        return None
    try:
        return tuple(int(p) for p in m.group(1).split("."))
    except ValueError:
        return None


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    a, b = _pad(a, b)
    return (a > b) - (a < b)


def _eq(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    return _cmp(a, b) == 0


def _prefix(version: tuple[int, ...], prefix: tuple[int, ...]) -> bool:
    return version[: len(prefix)] == prefix


# ---------------------------------------------------------------- PEP 440

_OPS = ("===", "==", "!=", ">=", "<=", "~=", ">", "<")


def _split_op(clause: str) -> tuple[str, str]:
    clause = clause.strip()
    for op in _OPS:
        if clause.startswith(op):
            return op, clause[len(op):].strip()
    return "==", clause  # bare version in a spec context means exact


def _clause_admits(op: str, raw_version: str) -> bool:
    if raw_version.endswith(".*"):
        prefix = parse_version(raw_version[:-2])
        if prefix is None:
            return True
        if op == "==":
            return _prefix(TARGET, prefix)
        if op == "!=":
            return not _prefix(TARGET, prefix)
        return True  # wildcard with other ops: conservative admit
    version = parse_version(raw_version)
    if version is None:
        return True  # unparsable: conservative admit
    if op in ("==", "==="):
        return _eq(TARGET, version)
    if op == "!=":
        return not _eq(TARGET, version)
    if op == ">=":
        return _cmp(TARGET, version) >= 0
    if op == "<=":
        return _cmp(TARGET, version) <= 0
    if op == ">":
        return _cmp(TARGET, version) > 0
    if op == "<":
        return _cmp(TARGET, version) < 0
    if op == "~=":
        # >= V, and == prefix of all but the last component of V.
        if _cmp(TARGET, version) < 0:
            return False
        if len(version) >= 2:
            return _prefix(TARGET, version[:-1])
        return True
    return True


def evaluate_pep440(specset: str | None) -> tuple[bool, bool]:
    """(pins, admits) for a PEP 440 specifier set (comma = AND)."""
    if specset is None or not str(specset).strip():
        return (False, True)  # no constraint at all
    clauses = [c.strip() for c in str(specset).split(",") if c.strip()]
    if not clauses:
        return (False, True)
    admits = True
    for clause in clauses:
        op, raw = _split_op(clause)
        if not _clause_admits(op, raw):
            admits = False
            break
    pins = False
    if len(clauses) == 1:
        op, raw = _split_op(clauses[0])
        if op in ("==", "===") and not raw.endswith(".*"):
            version = parse_version(raw)
            pins = version is not None and _eq(TARGET, version)
    return (pins, admits)


# ----------------------------------------------------------------- Poetry

def _caret_upper(version: tuple[int, ...]) -> tuple[int, ...]:
    for i, part in enumerate(version):
        if part != 0:
            return version[:i] + (part + 1,) + (0,) * (len(version) - i - 1)
    return version[:-1] + (version[-1] + 1,)


def _tilde_upper(version: tuple[int, ...]) -> tuple[int, ...]:
    if len(version) == 1:
        return (version[0] + 1,)
    if len(version) == 2:
        return (version[0], version[1] + 1)
    return version[:-2] + (version[-2] + 1,)


def _poetry_token_admits(token: str) -> bool:
    token = token.strip()
    if not token:
        return True
    if token == "*":
        return True
    if token.startswith("^"):
        version = parse_version(token[1:])
        if version is None:
            return True
        return _cmp(TARGET, version) >= 0 and _cmp(TARGET, _caret_upper(version)) < 0
    if token.startswith("~") and not token.startswith("~="):
        version = parse_version(token[1:])
        if version is None:
            return True
        return _cmp(TARGET, version) >= 0 and _cmp(TARGET, _tilde_upper(version)) < 0
    if token.endswith((".*", ".x", ".X")):
        prefix = parse_version(token.rsplit(".", 1)[0])
        return True if prefix is None else _prefix(TARGET, prefix)
    op, raw = _split_op(token)
    return _clause_admits(op, raw)


def _poetry_token_pins(token: str) -> bool:
    token = token.strip()
    if "*" in token or token.endswith((".x", ".X")):
        return False  # a wildcard range admits, but never pins exactly
    if token.startswith("=="):
        version = parse_version(token[2:])
        return version is not None and version == TARGET
    if token and token[0].isdigit():
        version = parse_version(token)
        return version is not None and version == TARGET
    return False


def evaluate_poetry(constraint: str | None) -> tuple[bool, bool]:
    """(pins, admits) for a Poetry version constraint (|| = OR)."""
    if constraint is None or not str(constraint).strip():
        return (False, True)
    text = str(constraint).strip()
    branches = [b.strip() for b in text.split("||")]
    admits = False
    for branch in branches:
        tokens = [t for t in re.split(r"[,\s]+", branch) if t]
        if all(_poetry_token_admits(t) for t in tokens):
            admits = True
            break
    pins = False
    if len(branches) == 1:
        tokens = [t for t in re.split(r"[,\s]+", branches[0]) if t]
        if len(tokens) == 1:
            pins = _poetry_token_pins(tokens[0])
    return (pins, admits)


# ------------------------------------------------------------------ conda

def evaluate_conda(spec: str | None) -> tuple[bool, bool]:
    """(pins, admits) for a conda matchspec version part.

    conda semantics: ``=1.107`` is a prefix match (1.107.*), ``=1.107.0``
    names the version itself; ``==`` is exact; comparison ops behave
    as in PEP 440; comma separates AND clauses.
    """
    if spec is None or not str(spec).strip():
        return (False, True)
    clauses = [c.strip() for c in str(spec).split(",") if c.strip()]
    if not clauses:
        return (False, True)
    admits = True
    pins = False
    for i, clause in enumerate(clauses):
        if clause.startswith("=="):
            version = parse_version(clause[2:])
            ok = True if version is None else _eq(TARGET, version)
            if ok and version is not None and version == TARGET and len(clauses) == 1:
                pins = True
        elif clause.startswith("=") or clause[0].isdigit():
            raw = clause.removeprefix("=")
            raw = raw.removesuffix(".*")
            version = parse_version(raw)
            ok = True if version is None else _prefix(TARGET, version)
            if ok and version is not None and version == TARGET and len(clauses) == 1:
                pins = True
        else:
            op, raw = _split_op(clause)
            ok = _clause_admits(op, raw)
        if not ok:
            admits = False
    if not admits:
        pins = False
    return (pins, admits)
