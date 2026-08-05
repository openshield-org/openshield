"""Require a Developer Certificate of Origin sign-off on each PR commit."""

import re
import subprocess
import sys
from typing import Iterable


SIGNOFF = re.compile(r"^Signed-off-by:\s+.+\s+<[^<>@\s]+@[^<>\s]+>$", re.IGNORECASE | re.MULTILINE)


def has_signoff(message: str) -> bool:
    """Return whether a commit message contains a well-formed DCO trailer."""
    return SIGNOFF.search(message) is not None


def commit_timestamp(commit: str) -> int:
    """Return a commit's recorded committer timestamp."""
    return int(
        subprocess.check_output(
            ["git", "show", "--no-patch", "--format=%ct", commit],
            text=True,
        ).strip()
    )


def commits_between(base: str, head: str, baseline: str) -> list[str]:
    """Return commits introduced between the pull request base and head.

    Commits reachable from ``baseline`` and commits recorded before that policy
    commit are exempt because they existed before DCO enforcement. The timestamp
    check covers still-open legacy branches whose commits are not part of the
    baseline's ancestry, while newer work on those branches remains enforced.

    Excludes merge commits: a `git merge origin/dev` inside a long-running PR
    branch produces a commit with Git's default merge message and no
    Signed-off-by trailer, through no fault of the author's own commits.
    GitHub's own DCO app skips merge commits for the same reason.
    """
    output = subprocess.check_output(
        ["git", "rev-list", "--reverse", "--no-merges", f"{base}..{head}", f"^{baseline}"],
        text=True,
    )
    baseline_timestamp = commit_timestamp(baseline)
    return [item for item in output.splitlines() if item and commit_timestamp(item) > baseline_timestamp]


def commit_message(commit: str) -> str:
    """Read one commit message without interpreting its contents as a command."""
    return subprocess.check_output(
        ["git", "show", "--no-patch", "--format=%B", commit],
        text=True,
    )


def unsigned_commits(commits: Iterable[str]) -> list[str]:
    """Return commit IDs that lack a valid Signed-off-by trailer."""
    return [commit for commit in commits if not has_signoff(commit_message(commit))]


def main() -> int:
    if len(sys.argv) != 4:
        print("Usage: check_dco.py <base-sha> <head-sha> <baseline-sha>", file=sys.stderr)
        return 2

    commits = commits_between(sys.argv[1], sys.argv[2], sys.argv[3])
    if not commits:
        print("No DCO-eligible pull request commits found.")
        return 0

    missing = unsigned_commits(commits)
    if missing:
        print("The following commits lack a valid DCO Signed-off-by trailer:", file=sys.stderr)
        for commit in missing:
            print(f"  {commit}", file=sys.stderr)
        print("Recreate or amend them with: git commit -s", file=sys.stderr)
        return 1

    print(f"DCO sign-off verified for {len(commits)} commit(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
