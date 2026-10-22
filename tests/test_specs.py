import pytest

from litellm_check.specs import (
    evaluate_conda,
    evaluate_pep440,
    evaluate_poetry,
    parse_version,
)


def test_parse_version():
    assert parse_version("1.107.0") == (1, 107, 0)
    assert parse_version("v1.106.2") == (1, 106, 2)
    assert parse_version("1.107.0rc1") == (1, 107, 0)
    assert parse_version("not-a-version") is None


@pytest.mark.parametrize("spec,want", [
    ("==1.107.0", (True, True)),
    ("==1.107.0.*", (False, True)),
    ("==1.107.*", (False, True)),
    ("==1.106.2", (False, False)),
    ("", (False, True)),
    ("  ", (False, True)),
    (">=1.100", (False, True)),
    (">=1.107.1", (False, False)),
    (">=1.100,<1.107", (False, False)),
    ("~=1.107.0", (False, True)),
    ("~=1.107", (False, True)),
    ("~=1.106", (False, True)),
    ("~=1.106.5", (False, False)),
    ("!=1.107.0", (False, False)),
    ("<1.107", (False, False)),
    ("<=1.107.0", (False, True)),
    ("== 1.107.0", (True, True)),
])
def test_pep440(spec, want):
    assert evaluate_pep440(spec) == want


@pytest.mark.parametrize("constraint,want", [
    ("1.107.0", (True, True)),
    ("==1.107.0", (True, True)),
    ("1.106.2", (False, False)),
    ("^1.106.2", (False, True)),
    ("^1.107.0", (False, True)),
    ("^2.0.0", (False, False)),
    ("~1.107", (False, True)),
    ("~1.107.0", (False, True)),
    ("~1.106.0", (False, False)),
    ("*", (False, True)),
    ("1.107.*", (False, True)),
    (">=1.100,<1.107", (False, False)),
    (">=2.0 || <1.0", (False, False)),
    ("", (False, True)),
])
def test_poetry(constraint, want):
    assert evaluate_poetry(constraint) == want


@pytest.mark.parametrize("spec,want", [
    ("=1.107.0", (True, True)),
    ("==1.107.0", (True, True)),
    ("=1.107", (False, True)),
    ("=1.106.2", (False, False)),
    ("1.106.2", (False, False)),
    (">=1.100", (False, True)),
    (">=1.100,<1.107", (False, False)),
    ("", (False, True)),
])
def test_conda(spec, want):
    assert evaluate_conda(spec) == want
