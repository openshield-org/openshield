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
different authorized signer. Every commit introduced by a pull request is
checked; a sign-off only in the pull request description is insufficient.

To repair the latest local commit before review:

```bash
git commit --amend --signoff --no-edit
git push --force-with-lease
```

For multiple commits, use an interactive rebase and add a sign-off to each
commit. Do not add another person's sign-off without their authorization.
