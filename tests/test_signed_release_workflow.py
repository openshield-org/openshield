"""Safety checks for the signed release workflow."""

from pathlib import Path

import yaml


WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "release.yml"


def _workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_release_workflow_has_keyless_attestation_permissions():
    assert _workflow()["permissions"] == {
        "contents": "write",
        "id-token": "write",
        "attestations": "write",
    }


def test_release_requires_verified_annotated_tag():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert 'object_type" != "tag"' in source
    assert ".verification.verified" in source
    assert 'verified" != "true"' in source


def test_release_attests_every_distributed_manifest():
    source = WORKFLOW.read_text(encoding="utf-8")
    action = "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373"
    assert source.count(action) == 3
    assert "openshield-${{ env.TAG }}.tar.gz" in source
    assert "openshield-${{ env.TAG }}-sbom.cyclonedx.json" in source
    assert "subject-path: dist/SHA256SUMS" in source


def test_release_artifact_is_deterministic_and_checksums_are_published():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "git archive --format=tar" in source
    assert "gzip --no-name" in source
    assert "sha256sum" in source
    assert "files: dist/*" in source
