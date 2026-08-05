# Developer Certificate of Origin

OpenShield uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
as its contribution authorization mechanism. A `Signed-off-by` trailer states
that the contributor is legally entitled to submit the work under the project's
license and agrees to the DCO certification.

Add the trailer automatically when committing:

```bash
git commit -s -m "feat: describe the change"
```

The name and email in the trailer should identify the contributor and should
match the commit author unless a documented contribution workflow requires a
different authorized signer. Every non-merge commit introduced by a pull
request is checked; a sign-off only in the pull request description is
insufficient.

DCO enforcement began with commit
`1d9469e162fce788bca839cfaf8a3e66ca35cf9b` (PR #208). Commits already
reachable from that baseline—or recorded before it—are exempt, so release pull
requests and still-open legacy branches do not retroactively reject work created
before the policy. New commits remain subject to DCO even when they are added to
a branch created before the baseline.

Merge commits (e.g. from running `git merge origin/dev` to bring your branch
up to date) are exempt — they carry Git's own default message, not your
authorship, so there is nothing for you to sign off on. Only commits you
authored yourself need the trailer.

To repair the latest local commit before review:

```bash
git commit --amend --signoff --no-edit
git push --force-with-lease
```

For multiple commits, use an interactive rebase and add a sign-off to each
commit. Do not add another person's sign-off without their authorization.
