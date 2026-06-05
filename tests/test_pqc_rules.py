"""Unit tests for post-quantum Azure rule modules."""

from types import SimpleNamespace

from scanner.rules import az_pqc_001, az_pqc_002, az_pqc_003


_VAULT_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault1"
)


class FakeAzureClient:
    def __init__(self, web_apps=None, vaults=None, keys=None, certificates=None):
        self._web_apps = web_apps if web_apps is not None else []
        self._vaults = vaults if vaults is not None else []
        self._keys = keys if keys is not None else []
        self._certificates = certificates if certificates is not None else []

    def get_web_apps(self):
        return self._web_apps

    def get_key_vaults(self):
        return self._vaults

    def get_key_vault_keys(self, vault_name):
        return self._keys

    def get_key_vault_certificates(self, vault_name):
        return self._certificates

    @staticmethod
    def parse_resource_id(resource_id):
        parts = resource_id.split("/")
        result = {"name": parts[-1]}
        if "resourceGroups" in parts:
            result["resource_group"] = parts[parts.index("resourceGroups") + 1]
        return result


def _enum_value(value):
    return SimpleNamespace(value=value)


def test_pqc_001_flags_app_service_tls_below_13():
    app = SimpleNamespace(
        id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/app1",
        name="app1",
        site_config=SimpleNamespace(min_tls_version="1.2"),
    )
    client = FakeAzureClient(web_apps=[app])

    findings = az_pqc_001.scan(client, "sub")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-PQC-001"
    assert findings[0]["metadata"]["min_tls_version"] == "1.2"


def test_pqc_001_ignores_tls_13():
    app = SimpleNamespace(
        id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/app1",
        name="app1",
        site_config=SimpleNamespace(min_tls_version="1.3"),
    )
    client = FakeAzureClient(web_apps=[app])

    assert az_pqc_001.scan(client, "sub") == []


def test_pqc_002_flags_rsa_key_vault_key():
    vault = SimpleNamespace(id=_VAULT_ID, name="vault1")
    key = SimpleNamespace(
        id=f"{_VAULT_ID}/keys/key1",
        name="key1",
        key_type=_enum_value("RSA"),
    )
    client = FakeAzureClient(vaults=[vault], keys=[key])

    findings = az_pqc_002.scan(client, "sub")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-PQC-002"
    assert findings[0]["metadata"]["key_type"] == "RSA"
    assert findings[0]["metadata"]["vault_name"] == "vault1"


def test_pqc_002_ignores_non_classical_key_type():
    vault = SimpleNamespace(id=_VAULT_ID, name="vault1")
    key = SimpleNamespace(
        id=f"{_VAULT_ID}/keys/key1",
        name="key1",
        key_type=_enum_value("oct-HSM"),
    )
    client = FakeAzureClient(vaults=[vault], keys=[key])

    assert az_pqc_002.scan(client, "sub") == []


def test_pqc_003_flags_classical_certificate_policy_key_type():
    vault = SimpleNamespace(id=_VAULT_ID, name="vault1")
    cert = SimpleNamespace(
        id=f"{_VAULT_ID}/certificates/cert1",
        name="cert1",
        policy=SimpleNamespace(
            key_properties=SimpleNamespace(key_type=_enum_value("EC"))
        ),
    )
    client = FakeAzureClient(vaults=[vault], certificates=[cert])

    findings = az_pqc_003.scan(client, "sub")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-PQC-003"
    assert findings[0]["metadata"]["key_type"] == "EC"


def test_pqc_003_ignores_certificate_without_classical_policy_key_type():
    vault = SimpleNamespace(id=_VAULT_ID, name="vault1")
    cert = SimpleNamespace(
        id=f"{_VAULT_ID}/certificates/cert1",
        name="cert1",
        policy=SimpleNamespace(
            key_properties=SimpleNamespace(key_type=_enum_value("ML-DSA"))
        ),
    )
    client = FakeAzureClient(vaults=[vault], certificates=[cert])

    assert az_pqc_003.scan(client, "sub") == []
