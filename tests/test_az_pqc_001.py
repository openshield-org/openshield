"""Tests for AZ-PQC-001 TLS version comparison (COR-007)."""

from scanner.rules.az_pqc_001 import _parse_version, _tls_version_below_13


def test_parses_simple_two_part_version():
    assert _parse_version("1.2") == (1, 2)


def test_parses_multi_digit_minor_version():
    assert _parse_version("1.10") == (1, 10)


def test_returns_none_for_unparseable_version():
    assert _parse_version("TLS_1_2") is None


def test_returns_none_for_none_input():
    assert _parse_version(None) is None


def test_below_13_for_1_0():
    assert _tls_version_below_13("1.0") is True


def test_below_13_for_1_2():
    assert _tls_version_below_13("1.2") is True


def test_not_below_13_for_1_3():
    assert _tls_version_below_13("1.3") is False


def test_not_below_13_for_none():
    """None means the field is absent/unknown, not a violation to flag here."""
    assert _tls_version_below_13(None) is False


def test_double_digit_minor_version_not_misordered_lexicographically():
    """The historical bug: naive string comparison ("1.10" < "1.3") says
    1.10 is below 1.3, because '1' < '3' lexicographically. Numerically,
    1.10 > 1.3, so it must NOT be flagged as below."""
    assert _tls_version_below_13("1.10") is False


def test_unparseable_version_is_not_flagged():
    """Garbage input must not fall back to a lexicographic guess."""
    assert _tls_version_below_13("not-a-version") is False


def test_higher_major_version_not_flagged():
    assert _tls_version_below_13("2.0") is False
