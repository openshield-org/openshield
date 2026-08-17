# Rules Reference

OpenShield currently ships 80 Azure scan rules. This table is generated from the module-level constants in `scanner/rules/`.

| Rule ID | Name | Severity | Category | CIS | NIST | ISO 27001 |
|---|---|---|---|---|---|---|
| AZ-CMP-001 | VM with Public IP and No Associated NSG on Network Interface | HIGH | Compute | 7.1 | PR.AC-3 | A.13.1.1 |
| AZ-CMP-002 | Virtual machine disk not protected by customer-managed key or ADE | HIGH | Compute | 7.2 | PR.DS-1 | A.10.1.1 |
| AZ-CMP-003 | VM Without Endpoint Protection Installed | HIGH | Compute | 8.2 | DE.CM-4 | A.12.2.1 |
| AZ-CMP-004 | VM Without Automatic OS Patching Enabled | HIGH | Compute | 8.3 | PR.IP-12 | A.12.6.1 |
| AZ-DB-001 | PostgreSQL Server Allows Public Network Access | HIGH | Database | 4.3.1 | PR.AC-3 | A.13.1.1 |
| AZ-DB-002 | Azure SQL Server Has No Auditing Configured | MEDIUM | Database | 4.1.3 | DE.CM-7 | A.12.4.1 |
| AZ-DB-003 | PostgreSQL Flexible Server SSL Enforcement Disabled | HIGH | Database | 4.3.6 | PR.DS-2 | A.10.1.1 |
| AZ-DB-004 | SQL Server Firewall Allows All Azure Services | HIGH | Database | 4.1.2 | PR.AC-3 | A.13.1.1 |
| AZ-IDN-001 | Service Principal Assigned Owner Role at Subscription Scope | HIGH | Identity | 1.24 | PR.AC-4 | A.9.2.3 |
| AZ-IDN-002 | No MFA Enforced on Admin Accounts via Conditional Access | HIGH | Identity | 1.2.4 | PR.AC-1 | A.9.4.2 |
| AZ-IDN-003 | Guest user invitations not restricted to admins in Entra ID | MEDIUM | Identity | 1.15 | PR.AC-1 | A.9.2.1 |
| AZ-IDN-004 | No Privileged Identity Management for Admin Roles | HIGH | Identity | 1.16 | PR.AC-4 | A.9.2.3 |
| AZ-IDN-005 | Guest User with High Privilege Role in Entra ID | HIGH | Identity | 1.3 | PR.AC-4 | A.9.2.3 |
| AZ-IDN-006 | Service Principal Client Secret Older Than 90 Days | HIGH | Identity | 1.14 | PR.AC-1 | A.9.4.3 |
| AZ-IDN-007 | Active User with No MFA Registered in Entra ID | HIGH | Identity | 1.1 | PR.AC-7 | A.9.4.2 |
| AZ-IDN-008 | Custom RBAC Role with Wildcard Permissions at Subscription Scope | HIGH | Identity | 1.23 | PR.AC-4 | A.9.2.3 |
| AZ-IDN-009 | No Activity Log Alert for Role Assignment Changes | MEDIUM | Identity | 5.2.1 | DE.CM-3 | A.12.4.1 |
| AZ-IDN-010 | App Registration Has No Owner | MEDIUM | Identity | N/A-IDN-010 | PR.AC-4 | A.9.2.1 |
| AZ-IDN-011 | App Registration Uses Insecure Redirect URI | HIGH | Identity | N/A-IDN-011 | PR.DS-2 | A.14.1.2 |
| AZ-IDN-012 | App Registration Enables OAuth Implicit Grant | MEDIUM | Identity | N/A-IDN-012 | PR.AC-3 | A.9.4.2 |
| AZ-IDN-013 | App Registration Uses Password Credentials | MEDIUM | Identity | N/A-IDN-013 | PR.AC-1 | A.9.4.3 |
| AZ-IDN-014 | Multi-Tenant App Registration Lacks Property Lock | HIGH | Identity | N/A-IDN-014 | PR.IP-1 | A.12.1.2 |
| AZ-IDN-015 | Managed Identity Has Privileged Subscription Role | HIGH | Identity | N/A-IDN-015 | PR.AC-4 | A.9.2.3 |
| AZ-KV-001 | Key Vault with Soft Delete Disabled | MEDIUM | KeyVault | N/A-KV-001 | PR.IP-4 | A.17.2.1 |
| AZ-KV-002 | Key Vault Allows Public Network Access Without Private Endpoint | HIGH | Key Vault | 8.7 | AC-17 | A.13.1.1 |
| AZ-KV-003 | Key Vault Without Diagnostic Logging Enabled | MEDIUM | Key Vault | 8.4 | DE.CM-7 | A.12.4.1 |
| AZ-KV-004 | Key Vault Purge Protection Disabled | MEDIUM | Key Vault | 8.5 | PR.IP-4 | A.17.2.1 |
| AZ-KV-005 | Key Vault Certificate Expiring Within 30 Days | MEDIUM | Key Vault | N/A-KV-005 | PR.MA-1 | A.10.1.2 |
| AZ-NET-001 | NSG Allows Unrestricted Inbound SSH from Any Source | HIGH | Network | 6.2 | PR.AC-3 | A.13.1.1 |
| AZ-NET-002 | NSG Allows Unrestricted Inbound RDP from Any Source | HIGH | Network | 6.3 | PR.AC-3 | A.13.1.1 |
| AZ-NET-003 | NSG allows unrestricted inbound on port 443 | HIGH | Network | 9.3 | SC-7 | A.13.1.1 |
| AZ-NET-004 | NSG with no rules configured | MEDIUM | Network | 9.2 | SC-7 | A.13.1.1 |
| AZ-NET-005 | Virtual network with no DDoS protection enabled | LOW | Network | 9.4 | SC-5 | A.13.1.1 |
| AZ-NET-006 | Public IP address unassociated with any resource | LOW | Network | 9.1 | CM-7 | A.13.1.1 |
| AZ-NET-007 | Application Gateway without WAF enabled | HIGH | Network | 9.6 | SI-3 | A.13.1.1 |
| AZ-NET-008 | Load balancer with no backend pool configured | LOW | Network | 9.7 | CM-7 | A.13.1.1 |
| AZ-NET-009 | VPN gateway using outdated IKE version | HIGH | Network | 9.5 | SC-8 | A.13.2.1 |
| AZ-NET-010 | Subnet with no network security group attached | HIGH | Network | 9.10 | SC-7 | A.13.1.1 |
| AZ-NET-011 | Network Watcher Not Enabled in All Regions | LOW | Network | 6.5 | DE.CM-7 | A.12.4.1 |
| AZ-NET-012 | NSG Flow Logs Not Enabled | MEDIUM | Network | 6.7 | DE.CM-1 | A.12.4.1 |
| AZ-NET-013 | Azure Firewall Not Enabled on Virtual Network | HIGH | Network | 6.4 | PR.AC-5 | A.13.1.1 |
| AZ-NET-014 | VNet Peering Configured Without Gateway Transit Restrictions | MEDIUM | Network | 6.6 | PR.AC-5 | A.13.1.1 |
| AZ-NET-015 | Public DNS Zone Exposes Internal Infrastructure Details | MEDIUM | Network | 9.8 | PR.AC-5 | A.13.1.1 |
| AZ-PQC-001 | TLS Using Classical Key Exchange Algorithm | HIGH | PostQuantum | 9.9 | PR.DS-2 | A.10.1.1 |
| AZ-PQC-002 | Key Vault Key Using Non-Quantum-Safe Algorithm | HIGH | PostQuantum | 8.1 | PR.DS-2 | A.10.1.1 |
| AZ-PQC-003 | Key Vault Certificate Using Non-Quantum-Safe Signature Algorithm | MEDIUM | PostQuantum | 8.9 | PR.DS-2 | A.10.1.1 |
| AZ-STOR-001 | Public Blob Access Enabled on Storage Account | HIGH | Storage | 3.5 | PR.AC-3 | A.9.4.1 |
| AZ-STOR-002 | Storage Account Allows HTTP Traffic (Not HTTPS-Only) | HIGH | Storage | 3.1 | PR.DS-2 | A.10.1.1 |
| AZ-STOR-003 | Storage Account Has No Lifecycle Management Policy | MEDIUM | Storage | 3.7 | PR.DS-3 | A.8.3.1 |
| AZ-STOR-004 | Storage Account Diagnostic Logging Disabled | MEDIUM | Storage | 3.3 | DE.CM-7 | A.12.4.1 |
| AZ-STOR-005 | Storage Account Not Using Geo-Redundant Replication | MEDIUM | Storage | 3.8 | PR.IP-4 | A.17.2.1 |
| AZ-AKS-001 | AKS Private Cluster Not Enabled | HIGH | Kubernetes | N/A-AKS-001 | PR.AC-3 | A.13.1.1 |
| AZ-AKS-002 | AKS Local Accounts Enabled | HIGH | Kubernetes | N/A-AKS-002 | PR.AC-1 | A.9.2.1 |
| AZ-AKS-003 | AKS Cluster Not Using Managed Identity | HIGH | Kubernetes | N/A-AKS-003 | PR.AC-1 | A.9.2.1 |
| AZ-AKS-004 | AKS Workload Identity Not Fully Enabled | MEDIUM | Kubernetes | N/A-AKS-004 | PR.AC-4 | A.9.2.3 |
| AZ-AKS-005 | AKS Azure Policy Add-on Not Enabled | MEDIUM | Kubernetes | N/A-AKS-005 | PR.IP-1 | A.12.1.2 |
| AZ-AKS-006 | AKS Node OS Automatic Upgrades Disabled | HIGH | Kubernetes | N/A-AKS-006 | PR.IP-12 | A.12.6.1 |
| AZ-BAK-001 | Backup Soft Delete Disabled or Below 35 Days | CRITICAL | Backup | N/A-BAK-001 | PR.IP-4 | A.12.3.1 |
| AZ-BAK-002 | Backup Vault Immutability Disabled | HIGH | Backup | N/A-BAK-002 | PR.IP-4 | A.12.3.1 |
| AZ-BAK-004 | Backup Multiuser Authorization Missing | HIGH | Backup | N/A-BAK-004 | PR.AC-4 | A.9.2.3 |
| AZ-BAK-006 | Backup Security Monitoring Disabled | MEDIUM | Backup | N/A-BAK-006 | DE.CM-1 | A.12.4.1 |
| AZ-FUNC-001 | Function App HTTPS Only Disabled | HIGH | Serverless | N/A-FUNC-001 | PR.DS-2 | A.13.2.1 |
| AZ-FUNC-002 | Function App Minimum TLS Below 1.2 | HIGH | Serverless | N/A-FUNC-002 | PR.DS-2 | A.13.2.1 |
| AZ-FUNC-003 | Function App FTP Publishing Enabled | MEDIUM | Serverless | N/A-FUNC-003 | PR.AC-5 | A.13.1.1 |
| AZ-FUNC-004 | Function App Remote Debugging Enabled | HIGH | Serverless | N/A-FUNC-004 | PR.AC-5 | A.13.1.1 |
| AZ-FUNC-005 | Function App Managed Identity Missing | MEDIUM | Serverless | N/A-FUNC-005 | PR.AC-5 | A.13.1.1 |
| AZ-PE-001 | Storage Public Network Access Enabled | HIGH | Network | N/A-PE-001 | PR.AC-5 | A.13.1.1 |
| AZ-PE-002 | Azure SQL Public Network Access Enabled | HIGH | Network | N/A-PE-002 | PR.AC-5 | A.13.1.1 |
| AZ-PE-003 | PostgreSQL Public Network Access Enabled | HIGH | Network | N/A-PE-003 | PR.AC-5 | A.13.1.1 |
| AZ-PE-004 | Web or Function App Public Network Access Enabled | HIGH | Network | N/A-PE-004 | PR.AC-5 | A.13.1.1 |
| AZ-PE-005 | Recovery Vault Public Network Access Enabled | HIGH | Network | N/A-PE-005 | PR.AC-5 | A.13.1.1 |
| AZ-PE-006 | Private Endpoint Connection Not Approved | MEDIUM | Network | N/A-PE-006 | PR.AC-5 | A.13.1.1 |
| AZ-SC-001 | Container Registry Admin User Enabled | HIGH | Supply Chain | N/A-SC-001 | PR.AC-1 | A.9.2.1 |
| AZ-SC-002 | Container Registry Public Network Access Enabled | HIGH | Supply Chain | N/A-SC-002 | PR.AC-5 | A.13.1.1 |
| AZ-SC-003 | Container Registry Allows Anonymous Pull | HIGH | Supply Chain | N/A-SC-003 | PR.AC-1 | A.9.2.1 |
| AZ-SC-004 | Container Registry Missing Retention or Quarantine Policy | MEDIUM | Supply Chain | N/A-SC-004 | PR.IP-1 | A.12.1.2 |
| AZ-SC-005 | Terraform State Storage Container Publicly Readable | CRITICAL | Supply Chain | N/A-SC-005 | PR.AC-5 | A.13.1.1 |
| AZ-SC-006 | Terraform State Storage Account Missing Versioning or Soft Delete | HIGH | Supply Chain | N/A-SC-006 | PR.IP-4 | A.12.3.1 |
| AZ-SC-007 | Pipeline Service Connection Scoped to Subscription | HIGH | Supply Chain | N/A-SC-007 | PR.AC-4 | A.9.2.3 |
| AZ-SC-008 | Pipeline Service Connection Uses Password Instead of Federated Credential | MEDIUM | Supply Chain | N/A-SC-008 | PR.AC-1 | A.9.4.3 |

SOC 2 mappings are maintained in `compliance/frameworks/soc2.json`.

Every rule has a matching remediation playbook in `playbooks/cli/fix_<rule_id_lowercase>.sh`.
