"""Tests for the dependency-free DCO enforcement helper."""

from unittest.mock import patch

from scripts.check_dco import commits_between, has_signoff, unsigned_commits


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


def test_commits_between_excludes_merge_commits():
    """A `git merge origin/dev` inside a PR branch has no Signed-off-by
    trailer and isn't the author's own commit — it must never be checked,
    or a legitimate PR gets blocked for merging the base branch in."""
    with patch("scripts.check_dco.subprocess.check_output", return_value="abc123\ndef456\n") as mock_run:
        result = commits_between("base-sha", "head-sha")

    assert result == ["abc123", "def456"]
    called_args = mock_run.call_args.args[0]
    assert "--no-merges" in called_args
