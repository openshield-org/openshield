"""Tests for the dependency-free DCO enforcement helper."""

import subprocess
from unittest.mock import patch

from scripts.check_dco import commit_timestamp, commits_between, has_signoff, main, unsigned_commits


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


def test_main_passes_when_every_commit_is_exempt():
    with (
        patch("scripts.check_dco.sys.argv", ["check_dco.py", "base", "head", "baseline"]),
        patch("scripts.check_dco.commits_between", return_value=[]),
    ):
        assert main() == 0


def test_commits_between_excludes_merge_commits():
    """A `git merge origin/dev` inside a PR branch has no Signed-off-by
    trailer and isn't the author's own commit — it must never be checked,
    or a legitimate PR gets blocked for merging the base branch in."""
    timestamps = {"baseline-sha": 100, "abc123": 101, "def456": 102}
    with (
        patch("scripts.check_dco.subprocess.check_output", return_value="abc123\ndef456\n") as mock_run,
        patch("scripts.check_dco.commit_timestamp", side_effect=timestamps.get),
    ):
        result = commits_between("base-sha", "head-sha", "baseline-sha")

    assert result == ["abc123", "def456"]
    called_args = mock_run.call_args.args[0]
    assert "--no-merges" in called_args
    assert "^baseline-sha" in called_args


def test_commits_between_exempts_legacy_side_branch_but_checks_new_work():
    timestamps = {"baseline": 100, "legacy": 90, "new": 110}
    with (
        patch("scripts.check_dco.subprocess.check_output", return_value="legacy\nnew\n"),
        patch("scripts.check_dco.commit_timestamp", side_effect=timestamps.get),
    ):
        assert commits_between("base", "head", "baseline") == ["new"]


def test_commit_timestamp_reads_committer_epoch():
    with patch("scripts.check_dco.subprocess.check_output", return_value="1234567890\n") as run:
        assert commit_timestamp("abc123") == 1234567890
    assert run.call_args.args[0] == ["git", "show", "--no-patch", "--format=%ct", "abc123"]


def _git(repository, *args):
    return subprocess.check_output(
        ["git", "-C", str(repository), *args],
        text=True,
    ).strip()


def _commit(repository, message):
    (repository / "history.txt").write_text(message, encoding="utf-8")
    _git(repository, "add", "history.txt")
    _git(repository, "commit", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def test_baseline_exempts_history_but_checks_new_work_from_old_branch(tmp_path, monkeypatch):
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "Test User")
    _git(repository, "config", "user.email", "test@example.com")

    old_commit = _commit(repository, "old unsigned commit")
    baseline = _commit(repository, "introduce DCO")
    _git(repository, "switch", "-c", "old-feature", old_commit)
    new_commit = _commit(repository, "new unsigned work")

    monkeypatch.chdir(repository)
    with patch(
        "scripts.check_dco.commit_timestamp",
        side_effect={baseline: 100, new_commit: 101}.get,
    ):
        assert commits_between(baseline, new_commit, baseline) == [new_commit]
