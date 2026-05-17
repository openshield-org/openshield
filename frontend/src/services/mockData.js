export const mockData = {
  score: {
    score: 68,
    max_score: 100,
  },

  findings: {
    count: 12,
    limit: 100,
    offset: 0,
    findings: [
      {
        id: 1,
        rule_id: 'AZ-STOR-001',
        rule_name: 'Storage account allows public blob access',
        severity: 'HIGH',
        category: 'Storage',
        resource_name: 'backupstorage',
        resource_type: 'Microsoft.Storage/storageAccounts',
        description: 'Blob container has public read access enabled',
        remediation: "Set 'allowBlobPublicAccess' to false",
        detected_at: '2024-01-20T14:22:00Z',
      },
      {
        id: 2,
        rule_id: 'AZ-DB-002',
        rule_name: 'SQL Database encryption not enabled',
        severity: 'HIGH',
        category: 'Database',
        resource_name: 'proddb',
        resource_type: 'Microsoft.Sql/servers/databases',
        description: 'Transparent Data Encryption (TDE) is not enabled',
        remediation: 'Enable TDE on the database',
        detected_at: '2024-01-19T10:15:00Z',
      },
      {
        id: 3,
        rule_id: 'AZ-NET-001',
        rule_name: 'Network Security Group allows SSH from Internet',
        severity: 'HIGH',
        category: 'Network',
        resource_name: 'web-nsg',
        resource_type: 'Microsoft.Network/networkSecurityGroups',
        description: 'SSH port 22 is open from 0.0.0.0/0',
        remediation: 'Restrict SSH access to specific IP ranges',
        detected_at: '2024-01-18T16:30:00Z',
      },
      {
        id: 4,
        rule_id: 'AZ-VM-005',
        rule_name: 'Virtual Machine missing OS disk encryption',
        severity: 'MEDIUM',
        category: 'Compute',
        resource_name: 'app-vm-01',
        resource_type: 'Microsoft.Compute/virtualMachines',
        description: 'VM disk is not encrypted',
        remediation: 'Enable Azure Disk Encryption',
        detected_at: '2024-01-17T09:00:00Z',
      },
      {
        id: 5,
        rule_id: 'AZ-NET-002',
        rule_name: 'Network Security Group allows RDP from Internet',
        severity: 'HIGH',
        category: 'Network',
        resource_name: 'admin-nsg',
        resource_type: 'Microsoft.Network/networkSecurityGroups',
        description: 'RDP port 3389 is open from 0.0.0.0/0',
        remediation: 'Restrict RDP access to specific IP ranges',
        detected_at: '2024-01-16T14:00:00Z',
      },
    ],
  },

  scans: {
    count: 1,
    scans: [
      {
        scan_id: 'scan-abc-123-def',
        subscription_id: 'sub-demo-001',
        started_at: '2024-01-20T14:00:00Z',
        completed_at: '2024-01-20T14:08:00Z',
        total_findings: 12,
      },
    ],
  },

  complianceCIS: {
    framework: 'CIS Microsoft Azure Foundations Benchmark',
    version: '2.0.0',
    total_controls: 30,
    passed: 24,
    failed: 6,
    score_percent: 80,
    controls: [
      {
        control_id: '3.5',
        control_name: "Ensure that 'Public access level' is set to Private for blob containers",
        rule_id: 'AZ-STOR-001',
        status: 'FAIL',
      },
      {
        control_id: '3.1',
        control_name: "Ensure that 'Secure transfer required' is set to 'Enabled'",
        rule_id: 'AZ-STOR-002',
        status: 'PASS',
      },
      {
        control_id: '6.2',
        control_name: 'Ensure that SSH access from the Internet is evaluated and restricted',
        rule_id: 'AZ-NET-001',
        status: 'FAIL',
      },
    ],
  },

  complianceNIST: {
    framework: 'NIST Cybersecurity Framework',
    version: '1.1',
    total_controls: 40,
    passed: 34,
    failed: 6,
    score_percent: 85,
    controls: [],
  },

  complianceISO: {
    framework: 'ISO 27001',
    version: '2013',
    total_controls: 40,
    passed: 30,
    failed: 10,
    score_percent: 75,
    controls: [],
  },
}

export default mockData