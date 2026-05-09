# Rules Reference

OpenShield currently ships 20 Azure scan rules. This table is generated from the module-level constants in `scanner/rules/`.

| Rule ID | Name | Severity | Category | CIS | NIST | ISO27001 |
|---|---|---|---|---|---|---|
| AZ-CMP-001 | VM with Public IP and No Associated NSG on Network Interface | HIGH | Compute | 7.2 | PR.AC-3 | A.13.1.1 |
| AZ-DB-001 | PostgreSQL Server Allows Public Network Access | HIGH | Database | 4.3.1 | PR.AC-3 | A.13.1.1 |
| AZ-DB-002 | Azure SQL Server Has No Auditing Configured | MEDIUM | Database | 4.1.3 | DE.CM-7 | A.12.4.1 |
| AZ-IDN-001 | Service Principal Assigned Owner Role at Subscription Scope | HIGH | Identity | 1.23 | PR.AC-4 | A.9.2.3 |
| AZ-IDN-002 | No MFA Enforced on Admin Accounts via Conditional Access | HIGH | Identity | 1.2.4 | PR.AC-1 | A.9.4.2 |
| AZ-KV-001 | Key Vault with Soft Delete Disabled | MEDIUM | KeyVault | 8.5 | PR.IP-4 | A.17.2.1 |
| AZ-KV-002 | Key Vault Allows Public Network Access Without Private Endpoint | HIGH | Key Vault | 8.3 | AC-17 | A.13.1.1 |
| AZ-NET-001 | NSG Allows Unrestricted Inbound SSH from Any Source | HIGH | Network | 6.2 | PR.AC-3 | A.13.1.1 |
| AZ-NET-002 | NSG Allows Unrestricted Inbound RDP from Any Source | HIGH | Network | 6.3 | PR.AC-3 | A.13.1.1 |
| AZ-NET-003 | NSG allows unrestricted inbound on port 443 | HIGH | Network | 9.3 | SC-7 | A.13.1.1 |
| AZ-NET-004 | NSG with no rules configured | MEDIUM | Network | 9.2 | SC-7 | A.13.1.1 |
| AZ-NET-005 | Virtual network with no DDoS protection enabled | LOW | Network | 9.4 | SC-5 | A.13.1.1 |
| AZ-NET-006 | Public IP address unassociated with any resource | LOW | Network | 9.1 | CM-7 | A.13.1.1 |
| AZ-NET-007 | Application Gateway without WAF enabled | HIGH | Network | 9.6 | SI-3 | A.13.1.1 |
| AZ-NET-008 | Load balancer with no backend pool configured | LOW | Network | 9.1 | CM-7 | A.13.1.1 |
| AZ-NET-009 | VPN gateway using outdated IKE version | HIGH | Network | 9.5 | SC-8 | A.13.2.1 |
| AZ-NET-010 | Subnet with no network security group attached | HIGH | Network | 9.2 | SC-7 | A.13.1.1 |
| AZ-STOR-001 | Public Blob Access Enabled on Storage Account | HIGH | Storage | 3.5 | PR.AC-3 | A.9.4.1 |
| AZ-STOR-002 | Storage Account Allows HTTP Traffic (Not HTTPS-Only) | HIGH | Storage | 3.1 | PR.DS-2 | A.10.1.1 |
| AZ-STOR-003 | Storage Account Has No Lifecycle Management Policy | MEDIUM | Storage | 3.7 | PR.DS-3 | A.8.3.1 |

SOC 2 mappings are maintained in `compliance/frameworks/soc2.json`.
