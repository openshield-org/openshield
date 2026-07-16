"""Tests for the dependency-free DCO enforcement helper."""

from unittest.mock import patch

from scripts.check_dco import has_signoff, unsigned_commits


def test_has_signoff_accepts_standard_dco_trailer():
    assert has_signoff("feat: change\n\nSigned-off-by: Tanvir Farhad <tanvir@example.com>\n")


def test_has_signoff_rejects_missing_or_malformed_trailer():
    assert not has_signoff("feat: unsigned change")
    assert not has_signoff("Signed-off-by: anonymous")
    assert not has_signoff("Signed-off-by: Name <not-an-email>")


def test_unsigned_commits_checks_each_commit():
    messages = {
        "a": "fix: one\n\nSigned-off-by: A User <a@example.com>",
        "b": "fix: two",
    }
    with patch("scripts.check_dco.commit_message", side_effect=messages.get):
        assert unsigned_commits(["a", "b"]) == ["b"]
