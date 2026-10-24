import pytest

from veroscudo.update import is_newer


@pytest.mark.parametrize("tag,current,expected", [
    ("v0.2.0", "0.1.1", True),
    ("1.0", "0.9.9", True),
    ("v0.1.1", "0.1.1", False),
    ("v0.1.0", "0.1.1", False),
    ("0.1.1.1", "0.1.1", True),
    ("latest", "0.1.1", False),
    ("v", "0.1.1", False),
    ("", "0.1.1", False),
    ("v1.2.3-beta", "0.1.1", False),
])
def test_is_newer(tag, current, expected):
    assert is_newer(tag, current) is expected
