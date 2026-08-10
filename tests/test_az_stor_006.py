import unittest
import scanner.rules.az_stor_006 as rule

class TestStorageHttpsRule(unittest.TestCase):

    def test_storage_https_disabled(self):
        # Mock storage accounts
        def mock_list_storage_accounts(subscription_id):
            return [
                {
                    "id": "/subscriptions/test-sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/teststorage",
                    "name": "teststorage",
                    "resourceGroup": "rg",
                    "properties": {
                        "supportsHttpsTrafficOnly": False
                    }
                }
            ]

        # Patch the function inside the rule
        rule.get_storage_accounts = mock_list_storage_accounts

        findings = rule.scan("test-sub")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "AZ-STORAGE-HTTPS-001")
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_storage_https_enabled(self):
        def mock_list_storage_accounts(subscription_id):
            return [
                {
                    "id": "/subscriptions/test-sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/teststorage",
                    "name": "teststorage",
                    "resourceGroup": "rg",
                    "properties": {
                        "supportsHttpsTrafficOnly": True
                    }
                }
            ]

        rule.get_storage_accounts = mock_list_storage_accounts

        findings = rule.scan("test-sub")

        self.assertEqual(findings, [])

if __name__ == "__main__":
    unittest.main()
