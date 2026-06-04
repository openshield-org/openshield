/**
 * OpenShield Website Content Database
 * 
 * Actual project data derived from the current repository state.
 */

const siteContent = {
    blog: [
        {
            id: "why-openshield",
            title: "Why We Built OpenShield: Solving the Cloud Security Accessibility Gap",
            date: "June 2, 2026",
            excerpt: "Cloud security shouldn't be a luxury reserved for the Fortune 500. We're democratizing CSPM for startups and researchers.",
            author: "OpenShield Maintainers",
            content: `
                <p class="mb-6">The modern cloud landscape is a double-edged sword. While it provides unprecedented agility, it also introduces a massive surface area for catastrophic errors. A single unchecked checkbox in the Azure Portal can expose a terabyte of PII to the public internet.</p>
                <h3 class="text-2xl font-bold mb-4 text-slate-900 dark:text-white">The "Zero Visibility" Problem</h3>
                <p class="mb-6">Startups, SMEs, and academic teams often operate in a security vacuum. They don't have the budget for enterprise tooling, yet they handle sensitive data that requires rigorous protection. OpenShield was born to bridge this gap.</p>
                <h3 class="text-2xl font-bold mb-4 text-slate-900 dark:text-white">The Road Ahead</h3>
                <p class="mb-6">We are fostering a community of security-conscious engineers who can contribute their own findings and remediation logic back to the world.</p>
            `
        },
        {
            id: "rule-engine-deep-dive",
            title: "Under the Hood: Engineering a Dynamic Rule Orchestration Engine",
            date: "May 28, 2026",
            excerpt: "A technical deep-dive into how OpenShield uses Python dynamic imports and SDK abstraction to scale security coverage.",
            author: "OpenShield Engineering",
            content: `
                <p class="mb-6">When we designed the OpenShield scanner, we knew that hardcoding security rules into the core engine was a recipe for technical debt. We needed a system where a security researcher could drop a new <code>.py</code> file into a folder and have it immediately active.</p>
                <h3 class="text-2xl font-bold mb-4 text-slate-900 dark:text-white">The AzureClient Abstraction</h3>
                <p class="mb-6">Rules shouldn't deal with the complexities of Azure's many SDKs. We built the <code>AzureClient</code> wrapper in <code>scanner/azure_client.py</code> to provide typed accessors and unified auth.</p>
            `
        },
        {
            id: "sentinel-automation",
            title: "Automating Microsoft Sentinel with OpenShield Findings",
            date: "May 20, 2026",
            excerpt: "Learn how to feed OpenShield's security posture data directly into Azure's enterprise SIEM for unified visibility.",
            author: "OpenShield Engineering",
            content: `
                <p class="mb-6">Security posture data is most valuable when it's integrated into your existing SOC workflows. OpenShield's Sentinel connector allows you to ingest findings into Log Analytics with a single command.</p>
            `
        }
    ],
    events: [],
    roadmap: [
        { id: "rm-1", title: "React Dashboard — Live on Vercel", status: "Shipped", category: "Frontend" },
        { id: "rm-6", title: "Real-world Breach Scenario Library", status: "Shipped", category: "Documentation" },
        { id: "rm-7", title: "Live Backend Integration (Resources, Drift, Prioritization, Playbook endpoints)", status: "Now", category: "Backend" },
        { id: "rm-2", title: "Automated Fix Workflows (GitHub Actions)", status: "Next", category: "Remediation" },
        { id: "rm-3", title: "Multi-cloud Support (AWS, GCP)", status: "Next", category: "Core Engine" },
        { id: "rm-4", title: "Custom Rule Creation Wizard", status: "Later", category: "UI/UX" },
        { id: "rm-5", title: "Enterprise Policy Enforcement Engine", status: "Later", category: "Core Engine" }
    ],
    showcase: [
        { name: "FinTech Startups", description: "Monitoring high-value Azure subscriptions for misconfigurations.", icon: "shield-check" },
        { name: "Academic Research", description: "Used by student teams to secure learning environments.", icon: "graduation-cap" },
        { name: "SME Cloud Ops", description: "Automating CIS & SOC2 compliance checks daily.", icon: "activity" },
        { name: "DevOps Teams", description: "Integrated into CI/CD for real-time security gates.", icon: "git-merge" },
        { name: "Security Researchers", description: "Building and sharing custom scan rules for the community.", icon: "search" }
    ],
    contributors: [
        { name: "ritiksah141", role: "Project Lead", handle: "ritiksah141" },
        { name: "Vishnu2707", role: "Core Maintainer", handle: "Vishnu2707" },
        { name: "parthrohit22", role: "Security Engineer", handle: "parthrohit22" },
        { name: "TFT444", role: "Core Maintainer", handle: "TFT444" }
    ],
    rules: [
        // Compute (4)
        {"id": "AZ-CMP-001", "name": "VM with Public IP and No NSG on Network Interface", "severity": "HIGH", "category": "Compute", "description": "A virtual machine has a public IP address assigned to its network interface but no Network Security Group protecting that interface. Without an NSG, all inbound ports are open to the internet by default.", "frameworks": {"CIS": "7.2", "NIST": "PR.AC-3", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-CMP-002", "name": "VM Disk Not Protected by Customer-Managed Key or ADE", "severity": "HIGH", "category": "Compute", "description": "One or more disks attached to this virtual machine are using platform-managed encryption only. CIS 7.2 requires disks to be protected using either Azure Disk Encryption (ADE) or a customer-managed key (CMK).", "frameworks": {"CIS": "7.2", "NIST": "PR.DS-1", "ISO27001": "A.10.1.1", "SOC2": "CC6.7"}},
        {"id": "AZ-CMP-003", "name": "VM Without Endpoint Protection Installed", "severity": "HIGH", "category": "Compute", "description": "VM has no recognised endpoint protection extension installed. Without it malware and ransomware can run undetected. CIS 8.2 requires an approved AV/EDR solution on all VMs.", "frameworks": {"CIS": "8.2", "NIST": "DE.CM-4", "ISO27001": "A.12.2.1", "SOC2": "CC6.8"}},
        {"id": "AZ-CMP-004", "name": "VM Without Automatic OS Patching Enabled", "severity": "HIGH", "category": "Compute", "description": "VM does not have automatic OS patching enabled. Unpatched VMs are vulnerable to known exploits. CIS 8.3 requires OS patches are applied in a timely manner.", "frameworks": {"CIS": "8.3", "NIST": "PR.IP-12", "ISO27001": "A.12.6.1", "SOC2": "CC7.1"}},
        // Database (4)
        {"id": "AZ-DB-001", "name": "PostgreSQL Server Allows Public Network Access", "severity": "HIGH", "category": "Database", "description": "The Azure Database for PostgreSQL server is configured to allow public network access. The server endpoint is reachable from the public internet, increasing the attack surface. Database servers should only be accessible from trusted private networks.", "frameworks": {"CIS": "4.3.1", "NIST": "PR.AC-3", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-DB-002", "name": "Azure SQL Server Has No Auditing Configured", "severity": "MEDIUM", "category": "Database", "description": "Azure SQL Server auditing is disabled. Without auditing, database access, schema changes, and failed login attempts are not logged, making forensic investigation and compliance reporting impossible.", "frameworks": {"CIS": "4.1.3", "NIST": "DE.CM-7", "ISO27001": "A.12.4.1"}},
        {"id": "AZ-DB-003", "name": "PostgreSQL Flexible Server SSL Enforcement Disabled", "severity": "HIGH", "category": "Database", "description": "The Azure Database for PostgreSQL Flexible Server has SSL enforcement disabled. Without SSL, data in transit between the application and database is transmitted in plaintext and is vulnerable to interception.", "frameworks": {"CIS": "4.3.6", "NIST": "PR.DS-2", "ISO27001": "A.10.1.1", "SOC2": "CC6.1"}},
        {"id": "AZ-DB-004", "name": "SQL Server Firewall Allows All Azure Services", "severity": "HIGH", "category": "Database", "description": "Azure SQL Server has the Allow access to Azure services firewall setting enabled. This creates a rule that permits any resource hosted in Azure, including services from other tenants, to connect to the SQL Server.", "frameworks": {"CIS": "4.1.2", "NIST": "PR.AC-3", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}},
        // Identity (4)
        {"id": "AZ-IDN-001", "name": "Service Principal Assigned Owner Role at Subscription Scope", "severity": "HIGH", "category": "Identity", "description": "A service principal holds the Owner role at subscription scope, granting it full control over all resources and the ability to assign roles to other principals. This violates the principle of least privilege.", "frameworks": {"CIS": "1.23", "NIST": "PR.AC-4", "ISO27001": "A.9.2.3"}},
        {"id": "AZ-IDN-002", "name": "No MFA Enforced on Admin Accounts via Conditional Access", "severity": "HIGH", "category": "Identity", "description": "No Conditional Access policy is enabled that requires multi-factor authentication for administrator accounts. Without MFA enforcement, a single compromised password is sufficient for an attacker to gain privileged access.", "frameworks": {"CIS": "1.2.4", "NIST": "PR.AC-1", "ISO27001": "A.9.4.2"}},
        {"id": "AZ-IDN-003", "name": "Guest User Invitations Not Restricted to Admins in Entra ID", "severity": "MEDIUM", "category": "Identity", "description": "Guest user invitations in Entra ID are not restricted to administrators. Any organisation member can invite external users without centralised review, bypassing formal external identity provisioning controls.", "frameworks": {"CIS": "1.15", "NIST": "PR.AC-1", "ISO27001": "A.9.2.1"}},
        {"id": "AZ-IDN-004", "name": "No Privileged Identity Management for Admin Roles", "severity": "HIGH", "category": "Identity", "description": "Privileged Identity Management (PIM) is not configured for one or more admin roles in Entra ID. Without PIM, admin roles are permanently assigned with no just-in-time access controls or time-bound activation.", "frameworks": {"CIS": "1.14", "NIST": "PR.AC-4", "ISO27001": "A.9.2.3", "SOC2": "CC6.3"}},
        // KeyVault (5)
        {"id": "AZ-KV-001", "name": "Key Vault with Soft Delete Disabled", "severity": "MEDIUM", "category": "KeyVault", "description": "Azure Key Vault soft delete is disabled. Without soft delete, secrets, keys, and certificates can be permanently destroyed immediately upon deletion by accident, a disgruntled insider, or an attacker.", "frameworks": {"CIS": "8.5", "NIST": "PR.IP-4", "ISO27001": "A.17.2.1"}},
        {"id": "AZ-KV-002", "name": "Key Vault Allows Public Network Access Without Private Endpoint", "severity": "HIGH", "category": "KeyVault", "description": "The Azure Key Vault is accessible over the public internet without a private endpoint configured. This increases the risk of unauthorized access to sensitive secrets, keys, and certificates.", "frameworks": {"CIS": "8.3", "NIST": "AC-17", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-KV-003", "name": "Key Vault Without Diagnostic Logging Enabled", "severity": "MEDIUM", "category": "KeyVault", "description": "Azure Key Vault diagnostic logging is not enabled. Without diagnostic logs, access to secrets, keys, and certificates is not recorded, reducing visibility into unauthorized access attempts.", "frameworks": {"CIS": "8.4", "NIST": "DE.CM-7", "ISO27001": "A.12.4.1", "SOC2": "CC7.2"}},
        {"id": "AZ-KV-004", "name": "Key Vault Purge Protection Disabled", "severity": "MEDIUM", "category": "KeyVault", "description": "Azure Key Vaults without purge protection enabled allow permanent deletion of vaults and their secrets, keys, and certificates during the soft-delete retention period. This can result in irrecoverable loss of cryptographic material.", "frameworks": {"CIS": "8.6", "NIST": "PR.IP-4", "ISO27001": "A.17.2.1", "SOC2": "CC9.1"}},
        {"id": "AZ-KV-005", "name": "Key Vault Certificate Expiring Within 30 Days", "severity": "MEDIUM", "category": "KeyVault", "description": "A certificate stored in Azure Key Vault is expiring within 30 days and does not have auto-renewal configured. Expired certificates cause immediate service outages, broken HTTPS connections, and failed authentication flows.", "frameworks": {"CIS": "8.5", "NIST": "PR.MA-1", "ISO27001": "A.10.1.2", "SOC2": "CC9.1"}},
        // Network (14)
        {"id": "AZ-NET-001", "name": "NSG Allows Unrestricted Inbound SSH from Any Source", "severity": "HIGH", "category": "Network", "description": "The Network Security Group has an Allow rule for inbound TCP port 22 (SSH) from any source address. Exposing SSH to the internet dramatically increases the attack surface and risk of brute-force attacks.", "frameworks": {"CIS": "6.2", "NIST": "PR.AC-3", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-NET-002", "name": "NSG Allows Unrestricted Inbound RDP from Any Source", "severity": "HIGH", "category": "Network", "description": "The Network Security Group has an Allow rule for inbound TCP port 3389 (RDP) from any source address. Exposing RDP to the internet is one of the most common initial access vectors for ransomware and credential-stuffing attacks.", "frameworks": {"CIS": "6.3", "NIST": "PR.AC-3", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-NET-003", "name": "NSG Allows Unrestricted Inbound on Port 443", "severity": "HIGH", "category": "Network", "description": "A Network Security Group has an inbound rule allowing unrestricted access on port 443 from any source. While HTTPS is encrypted, exposing port 443 to the entire internet increases the attack surface. Review manually before remediating public-facing web services.", "frameworks": {"CIS": "9.3", "NIST": "SC-7", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-NET-004", "name": "NSG with No Rules Configured", "severity": "MEDIUM", "category": "Network", "description": "A Network Security Group exists but has no custom security rules configured. An empty NSG relies entirely on Azure default rules which may not meet your security requirements.", "frameworks": {"CIS": "9.2", "NIST": "SC-7", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-NET-005", "name": "Virtual Network with No DDoS Protection Enabled", "severity": "LOW", "category": "Network", "description": "The virtual network does not have Azure DDoS Protection Standard enabled. Without DDoS protection, the network is vulnerable to volumetric attacks that can overwhelm resources and cause service outages.", "frameworks": {"CIS": "9.4", "NIST": "SC-5", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-NET-006", "name": "Public IP Address Unassociated with Any Resource", "severity": "LOW", "category": "Network", "description": "A public IP address exists in the subscription but is not associated with any resource. Unassociated public IPs represent unnecessary cost and attack surface and may indicate leftover resources from decommissioned workloads.", "frameworks": {"CIS": "9.1", "NIST": "CM-7", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-NET-007", "name": "Application Gateway Without WAF Enabled", "severity": "HIGH", "category": "Network", "description": "An Application Gateway exists without Web Application Firewall enabled. Without WAF, the application is unprotected against common web exploits such as SQL injection, XSS, and OWASP Top 10 attacks.", "frameworks": {"CIS": "9.6", "NIST": "SI-3", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-NET-008", "name": "Load Balancer with No Backend Pool Configured", "severity": "LOW", "category": "Network", "description": "A load balancer exists in the subscription but has no backend pool configured. It is either misconfigured or a leftover resource from a decommissioned workload, representing unnecessary cost.", "frameworks": {"CIS": "9.1", "NIST": "CM-7", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-NET-009", "name": "VPN Gateway Using Outdated IKE Version", "severity": "HIGH", "category": "Network", "description": "A VPN gateway is configured to use IKEv1 which is an outdated and less secure version of the Internet Key Exchange protocol. IKEv1 is vulnerable to several known attacks and lacks features present in IKEv2.", "frameworks": {"CIS": "9.5", "NIST": "SC-8", "ISO27001": "A.13.2.1"}},
        {"id": "AZ-NET-010", "name": "Subnet with No Network Security Group Attached", "severity": "HIGH", "category": "Network", "description": "A subnet exists without a Network Security Group attached. Without an NSG at the subnet level, all resources deployed into that subnet have no network layer access control.", "frameworks": {"CIS": "9.2", "NIST": "SC-7", "ISO27001": "A.13.1.1"}},
        {"id": "AZ-NET-011", "name": "Network Watcher Not Enabled in All Regions", "severity": "LOW", "category": "Network", "description": "Network Watcher is not enabled in one or more Azure regions where resources are deployed. Network Watcher provides network monitoring, diagnostics, and logging capabilities essential for incident investigation.", "frameworks": {"CIS": "6.5", "NIST": "DE.CM-7", "ISO27001": "A.12.4.1", "SOC2": "CC7.2"}},
        {"id": "AZ-NET-012", "name": "NSG Flow Logs Not Enabled", "severity": "MEDIUM", "category": "Network", "description": "Network Security Group flow logs are not enabled. Without flow logs, network traffic is not auditable and attacker movement through the network cannot be reconstructed.", "frameworks": {"CIS": "6.5", "NIST": "DE.CM-1", "ISO27001": "A.12.4.1", "SOC2": "CC7.2"}},
        {"id": "AZ-NET-013", "name": "Azure Firewall Not Enabled on Virtual Network", "severity": "HIGH", "category": "Network", "description": "The virtual network has no Azure Firewall deployed or associated. Relying only on NSGs leaves the network without a centralized perimeter inspection, logging, and threat-filtering layer.", "frameworks": {"CIS": "6.4", "NIST": "PR.AC-5", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}},
        {"id": "AZ-NET-014", "name": "VNet Peering Configured Without Gateway Transit Restrictions", "severity": "MEDIUM", "category": "Network", "description": "A Virtual Network peering connection has gateway transit enabled, potentially enabling lateral movement between network zones that should be isolated from each other.", "frameworks": {"CIS": "6.4", "NIST": "PR.AC-5", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}},
        // Storage (5)
        {"id": "AZ-STOR-001", "name": "Public Blob Access Enabled on Storage Account", "severity": "HIGH", "category": "Storage", "description": "Storage accounts with public blob access enabled allow unauthenticated read access to blob data over the internet. This setting can expose sensitive files, backups, or configuration data to any external actor.", "frameworks": {"CIS": "3.5", "NIST": "PR.AC-3", "ISO27001": "A.9.4.1"}},
        {"id": "AZ-STOR-002", "name": "Storage Account Allows HTTP Traffic (Not HTTPS-Only)", "severity": "HIGH", "category": "Storage", "description": "Storage accounts that do not enforce HTTPS-only traffic allow data to be transmitted in plaintext over HTTP. This exposes credentials and data to man-in-the-middle attacks and interception.", "frameworks": {"CIS": "3.1", "NIST": "PR.DS-2", "ISO27001": "A.10.1.1"}},
        {"id": "AZ-STOR-003", "name": "Storage Account Has No Lifecycle Management Policy", "severity": "MEDIUM", "category": "Storage", "description": "The storage account has no lifecycle management policy configured. Without a lifecycle policy, blobs accumulate indefinitely, increasing storage costs and the attack surface from retained data.", "frameworks": {"CIS": "3.7", "NIST": "PR.DS-3", "ISO27001": "A.8.3.1"}},
        {"id": "AZ-STOR-004", "name": "Storage Account Diagnostic Logging Disabled", "severity": "MEDIUM", "category": "Storage", "description": "Azure Monitor diagnostic logging is not fully enabled for the storage account. StorageRead, StorageWrite, and StorageDelete must all be enabled. Without logging, data exfiltration or unauthorised access cannot be detected or investigated.", "frameworks": {"CIS": "3.3", "NIST": "DE.CM-7", "ISO27001": "A.12.4.1", "SOC2": "CC7.2"}},
        {"id": "AZ-STOR-005", "name": "Storage Account Not Using Geo-Redundant Replication", "severity": "MEDIUM", "category": "Storage", "description": "This storage account is configured with a non-geo-redundant replication SKU. Locally redundant and zone-redundant storage replicate data only within a single region. A regional outage could result in data unavailability or loss.", "frameworks": {"CIS": "3.1", "NIST": "PR.IP-4", "ISO27001": "A.17.2.1", "SOC2": "A1.2"}},
        // Post-Quantum Cryptography (3) — unique to OpenShield; no competitor OSS CSPM tool scans for quantum-vulnerable assets
        {"id": "AZ-PQC-001", "name": "TLS Using Classical Key Exchange Algorithm", "severity": "HIGH", "category": "PostQuantum", "description": "The resource is configured with TLS using classical key exchange algorithms such as RSA or ECDH. Adversaries are executing Harvest Now Decrypt Later attacks — collecting encrypted traffic today to decrypt once quantum computers are available. Maps to NIST FIPS 203 (ML-KEM) migration requirements.", "frameworks": {"CIS": "9.1", "NIST": "PR.DS-2", "ISO27001": "A.10.1.1", "SOC2": "CC6.7"}},
        {"id": "AZ-PQC-002", "name": "Key Vault Key Using Non-Quantum-Safe Algorithm", "severity": "HIGH", "category": "PostQuantum", "description": "The Key Vault contains RSA or ECC keys vulnerable to Shor's algorithm on quantum computers. A sufficiently powerful quantum computer can break these keys, compromising all data encrypted or signed with them. Maps to NIST FIPS 204 (ML-DSA) migration requirements.", "frameworks": {"CIS": "8.1", "NIST": "PR.DS-2", "ISO27001": "A.10.1.2", "SOC2": "CC6.7"}},
        {"id": "AZ-PQC-003", "name": "Key Vault Certificate Using Non-Quantum-Safe Signature Algorithm", "severity": "MEDIUM", "category": "PostQuantum", "description": "The Key Vault contains certificates signed using RSA or ECDSA algorithms, vulnerable to Shor's algorithm. Certificates used for TLS, authentication, and code signing will need migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) as certificate authorities add post-quantum support.", "frameworks": {"CIS": "8.5", "NIST": "PR.DS-2", "ISO27001": "A.10.1.2", "SOC2": "CC6.7"}}
    ],
    ecosystem: [
        {
            id: "scanner",
            title: "Core Scanner Engine",
            description: "A multi-threaded Python engine designed for high-speed discovery and assessment of Azure resource configurations.",
            icon: "shield",
            color: "brand"
        },
        {
            id: "rules",
            title: "Security Rule Library",
            description: "28+ extensible Python modules mapping technical configurations to CIS, NIST, ISO, and SOC2 frameworks.",
            icon: "library",
            color: "purple"
        },
        {
            id: "playbooks",
            title: "Remediation Playbooks",
            description: "Atomic Azure CLI scripts that provide instant fixes for detected vulnerabilities, closing the defense loop.",
            icon: "zap",
            color: "emerald"
        },
        {
            id: "sentinel",
            title: "SIEM Integration",
            description: "Native Microsoft Sentinel connectors for real-time ingestion of findings into enterprise security pipelines.",
            icon: "layers",
            color: "cyan"
        }
    ],
    docs: [
        {
            id: "intro",
            title: "Introduction",
            content: `
                <div class="mb-12 bg-white/50 dark:bg-white/[0.02] border border-slate-200 dark:border-white/10 p-8 md:p-12 rounded-[2.5rem] backdrop-blur-xl shadow-sm text-center">
                    <h3 class="text-4xl lg:text-5xl font-black mb-4 tracking-tight text-slate-900 dark:text-white">Cloud Security,<br><span class="text-brand-500">Purely Open.</span></h3>
                    <p class="text-lg text-slate-600 dark:text-slate-400 max-w-2xl mx-auto m-0">OpenShield is the industry's first community-driven CSPM designed specifically for high-speed engineering teams.</p>
                </div>

                <div class="grid md:grid-cols-2 gap-8 mb-20">
                    <div class="group bg-white dark:bg-white/[0.02] border border-slate-200 dark:border-white/10 p-10 rounded-[2.5rem] hover:border-brand-500/50 transition-all">
                        <div class="w-14 h-14 bg-brand-500/10 text-brand-500 rounded-2xl flex items-center justify-center mb-8">
                            <i data-lucide="eye" class="w-7 h-7"></i>
                        </div>
                        <h4 class="text-2xl font-bold mb-4 dark:text-white">Audit the Auditor</h4>
                        <p class="text-slate-600 dark:text-slate-400 leading-relaxed">No black boxes. Every security check is a human-readable Python module that your team can audit, modify, and extend in minutes.</p>
                    </div>
                    <div class="group bg-white dark:bg-white/[0.02] border border-slate-200 dark:border-white/10 p-10 rounded-[2.5rem] hover:border-purple-500/50 transition-all">
                        <div class="w-14 h-14 bg-purple-500/10 text-purple-500 rounded-2xl flex items-center justify-center mb-8">
                            <i class="fas fa-shield-halved fa-fw text-2xl"></i>
                        </div>
                        <h4 class="text-2xl font-bold mb-4 dark:text-white">Zero Trust Boundary</h4>
                        <p class="text-slate-600 dark:text-slate-400 leading-relaxed">OpenShield runs entirely within your tenant. Your security findings and credentials never leave your control, ensuring total data sovereignty.</p>
                    </div>
                </div>

                <div class="bg-slate-900 dark:bg-slate-100 rounded-[3rem] p-12 text-white dark:text-slate-900 overflow-hidden relative shadow-2xl">
                    <div class="relative z-10">
                        <h4 class="text-3xl font-bold mb-4 text-white dark:text-slate-900">Scale with Confidence</h4>
                        <p class="text-slate-400 dark:text-slate-600 mb-8 max-w-xl">Whether you're a two-person startup or a growing enterprise, OpenShield scales to monitor thousands of resources across multiple subscriptions with zero performance degradation.</p>
                        <button onclick="showDocPage('quick-start')" class="bg-white dark:bg-slate-900 text-slate-900 dark:text-white px-8 py-3 rounded-xl font-bold hover:scale-105 transition-transform shadow-xl">Get Started Now</button>
                    </div>
                    <i data-lucide="zap" class="absolute -right-10 -bottom-10 w-64 h-64 text-white/5 dark:text-slate-900/10 rotate-12"></i>
                </div>
            `
        },
        {
            id: "quick-start",
            title: "Quick Start",
            content: `
                <h3 class="text-3xl font-bold mb-8">Enterprise Deployment</h3>
                <p class="mb-10 text-slate-600 dark:text-slate-400">Deploy OpenShield for production monitoring in three steps.</p>
                
                <div class="grid gap-10">
                    <!-- Step 1 -->
                    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/10 p-10 rounded-[2.5rem] shadow-sm">
                        <div class="flex items-center space-x-5 mb-8">
                            <span class="shrink-0 w-10 h-10 bg-slate-900 dark:bg-white text-white dark:text-slate-900 rounded-full flex items-center justify-center font-bold text-lg">1</span>
                            <h4 class="text-2xl font-bold dark:text-white m-0 leading-none">Environment & Installation</h4>
                        </div>
                        <p class="mb-8 text-slate-600 dark:text-slate-400 text-lg">Clone the engine and install dependencies in an isolated virtual environment.</p>
                        
                        <div class="relative rounded-2xl overflow-hidden bg-slate-900 shadow-2xl border border-slate-800">
                            <div class="flex items-center px-4 py-3 bg-slate-800/50 border-b border-slate-800">
                                <div class="flex space-x-2">
                                    <div class="w-2.5 h-2.5 rounded-full bg-[#ff5f56]"></div>
                                    <div class="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]"></div>
                                    <div class="w-2.5 h-2.5 rounded-full bg-[#27c93f]"></div>
                                </div>
                                <div class="mx-auto text-[10px] text-slate-500 font-mono tracking-widest uppercase">bash : setup</div>
                            </div>
                            <pre class="p-6 text-sm text-brand-400 font-mono overflow-x-auto"><code>git clone https://github.com/openshield-org/openshield.git\ncd openshield\npython3 -m venv venv\nsource venv/bin/activate\npip install -r requirements.txt</code></pre>
                        </div>
                    </div>

                    <!-- Step 2 -->
                    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/10 p-10 rounded-[2.5rem] shadow-sm">
                        <div class="flex items-center space-x-5 mb-8">
                            <span class="shrink-0 w-10 h-10 bg-slate-900 dark:bg-white text-white dark:text-slate-900 rounded-full flex items-center justify-center font-bold text-lg">2</span>
                            <h4 class="text-2xl font-bold dark:text-white m-0 leading-none">Enterprise Identity (RBAC)</h4>
                        </div>
                        <p class="mb-8 text-slate-600 dark:text-slate-400 text-lg">Provision a Service Principal with <code>Reader</code> access for secure, automated scanning.</p>
                        
                        <div class="relative rounded-2xl overflow-hidden bg-slate-900 shadow-2xl border border-slate-800">
                            <div class="flex items-center px-4 py-3 bg-slate-800/50 border-b border-slate-800">
                                <div class="flex space-x-2">
                                    <div class="w-2.5 h-2.5 rounded-full bg-[#ff5f56]"></div>
                                    <div class="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]"></div>
                                    <div class="w-2.5 h-2.5 rounded-full bg-[#27c93f]"></div>
                                </div>
                                <div class="mx-auto text-[10px] text-slate-500 font-mono tracking-widest uppercase">bash : identity</div>
                            </div>
                            <pre class="p-6 text-sm text-brand-400 font-mono overflow-x-auto"><code># Create Service Principal\naz ad sp create-for-rbac --name "OpenShieldScanner" --role Reader --scopes /subscriptions/{sub-id}</code></pre>
                        </div>
                    </div>

                    <!-- Step 3 -->
                    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/10 p-10 rounded-[2.5rem] shadow-sm">
                        <div class="flex items-center space-x-5 mb-8">
                            <span class="shrink-0 w-10 h-10 bg-slate-900 dark:bg-white text-white dark:text-slate-900 rounded-full flex items-center justify-center font-bold text-lg">3</span>
                            <h4 class="text-2xl font-bold dark:text-white m-0 leading-none">SIEM Ingestion & Monitoring</h4>
                        </div>
                        <p class="mb-8 text-slate-600 dark:text-slate-400 text-lg">Export credentials and pipe findings directly into Microsoft Sentinel for real-time visibility.</p>
                        
                        <div class="relative rounded-2xl overflow-hidden bg-slate-900 shadow-2xl border border-slate-800">
                            <div class="flex items-center px-4 py-3 bg-slate-800/50 border-b border-slate-800">
                                <div class="flex space-x-2">
                                    <div class="w-2.5 h-2.5 rounded-full bg-[#ff5f56]"></div>
                                    <div class="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]"></div>
                                    <div class="w-2.5 h-2.5 rounded-full bg-[#27c93f]"></div>
                                </div>
                                <div class="mx-auto text-[10px] text-slate-500 font-mono tracking-widest uppercase">bash : monitor</div>
                            </div>
                            <pre class="p-6 text-sm text-brand-400 font-mono overflow-x-auto"><code># Configuration\nexport AZURE_CLIENT_ID="xxx"\nexport AZURE_CLIENT_SECRET="xxx"\nexport AZURE_TENANT_ID="xxx"\nexport SENTINEL_WORKSPACE_ID="xxx"\nexport SENTINEL_SHARED_KEY="xxx"\n\n# Execute & Ingest\npython scanner/engine.py\npython sentinel/ingest.py scanner/output/findings.json</code></pre>
                        </div>
                    </div>
                </div>
            `
        },
        {
            id: "architecture",
            title: "Architecture",
            content: `
                <h3 class="text-3xl font-bold mb-8">Modular Enterprise Design</h3>
                <p class="mb-8 text-slate-600 dark:text-slate-400">OpenShield is engineered for modularity. The core engine acts as a high-speed orchestrator, while security intelligence is decoupled into isolated modules.</p>
                
                <div class="relative rounded-2xl overflow-hidden bg-slate-900 shadow-2xl border border-slate-800 mb-12">
                    <div class="flex items-center px-4 py-3 bg-slate-800/50 border-b border-slate-800">
                        <div class="flex space-x-2">
                            <div class="w-2.5 h-2.5 rounded-full bg-[#ff5f56]"></div>
                            <div class="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]"></div>
                            <div class="w-2.5 h-2.5 rounded-full bg-[#27c93f]"></div>
                        </div>
                        <div class="mx-auto text-[10px] text-slate-500 font-mono tracking-widest uppercase">logic : core</div>
                    </div>
                    <pre class="p-8 text-slate-400 font-mono text-sm leading-relaxed">ScanEngine\n  ├── load_rules()       # Dynamic module discovery\n  ├── run_scan()         # Multi-threaded execution\n  │    └── Rule Module   # Isolated .py module\n  │          └── scan()  # Execution entry point\n  └── AzureClient        # Unified SDK abstraction</pre>
                </div>

                <h4 class="text-xl font-bold mb-6 dark:text-white">The Three Pillars</h4>
                <div class="grid gap-6 mb-12">
                    <div class="flex items-start p-6 bg-slate-50 dark:bg-white/5 rounded-3xl border border-slate-200 dark:border-white/10">
                        <div class="w-10 h-10 bg-slate-900/5 dark:bg-white/5 text-slate-900 dark:text-white rounded-xl flex items-center justify-center mr-4 shrink-0"><i data-lucide="search" class="w-5 h-5"></i></div>
                        <div>
                            <h5 class="font-bold dark:text-white mb-1">Scanner Engine</h5>
                            <p class="text-sm text-slate-600 dark:text-slate-400">The multi-threaded Python core that handles discovery, authentication, and rule orchestration without global state interference.</p>
                        </div>
                    </div>
                    <div class="flex items-start p-6 bg-slate-50 dark:bg-white/5 rounded-3xl border border-slate-200 dark:border-white/10">
                        <div class="w-10 h-10 bg-slate-900/5 dark:bg-white/5 text-slate-900 dark:text-white rounded-xl flex items-center justify-center mr-4 shrink-0"><i data-lucide="database" class="w-5 h-5"></i></div>
                        <div>
                            <h5 class="font-bold dark:text-white mb-1">PostgreSQL Storage</h5>
                            <p class="text-sm text-slate-600 dark:text-slate-400">A structured relational database that persists findings, scan history, and framework mappings for long-term posture analysis.</p>
                        </div>
                    </div>
                    <div class="flex items-start p-6 bg-slate-50 dark:bg-white/5 rounded-3xl border border-slate-200 dark:border-white/10">
                        <div class="w-10 h-10 bg-slate-900/5 dark:bg-white/5 text-slate-900 dark:text-white rounded-xl flex items-center justify-center mr-4 shrink-0"><i data-lucide="server" class="w-5 h-5"></i></div>
                        <div>
                            <h5 class="font-bold dark:text-white mb-1">REST API Gateway</h5>
                            <p class="text-sm text-slate-600 dark:text-slate-400">A Flask-powered interface that exposes findings and real-time security scores to external dashboards and automation pipelines.</p>
                        </div>
                    </div>
                </div>

                <h4 class="text-xl font-bold mb-6 dark:text-white">SIEM Ingestion</h4>
                <p class="text-slate-600 dark:text-slate-400 mb-8 text-lg">For enterprise environments, OpenShield findings can be streamed directly into Microsoft Sentinel using the ingestion pipeline.</p>
                <div class="relative rounded-2xl overflow-hidden bg-slate-900 shadow-2xl border border-slate-800">
                    <div class="flex items-center px-4 py-3 bg-slate-800/50 border-b border-slate-800">
                        <div class="flex space-x-2">
                            <div class="w-2.5 h-2.5 rounded-full bg-[#ff5f56]"></div>
                            <div class="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]"></div>
                            <div class="w-2.5 h-2.5 rounded-full bg-[#27c93f]"></div>
                        </div>
                        <div class="mx-auto text-[10px] text-slate-500 font-mono tracking-widest uppercase">logic : sentinel</div>
                    </div>
                    <pre class="p-8 text-emerald-500 font-mono text-sm leading-relaxed">JSON Finding\n  └── HMAC Signature\n       └── Azure Log Analytics API\n             └── Microsoft Sentinel Dashboard</pre>
                </div>
            `
        },
        {
            id: "adding-rules",
            title: "Adding Rules",
            content: `
                <h3 class="text-3xl font-bold mb-8">Contribute a Rule</h3>
                <p class="mb-8 text-slate-600 dark:text-slate-400">Adding a rule is as simple as dropping a Python file into <code>scanner/rules/</code>. No core engine changes required.</p>
                
                <div class="relative rounded-2xl overflow-hidden bg-slate-900 shadow-2xl border border-slate-800 mb-12">
                    <div class="flex items-center px-4 py-3 bg-slate-800/50 border-b border-slate-800">
                        <div class="flex space-x-2">
                            <div class="w-2.5 h-2.5 rounded-full bg-[#ff5f56]"></div>
                            <div class="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]"></div>
                            <div class="w-2.5 h-2.5 rounded-full bg-[#27c93f]"></div>
                        </div>
                        <div class="mx-auto text-[10px] text-slate-500 font-mono tracking-widest uppercase">python : rule_template.py</div>
                    </div>
                    <pre class="p-8 text-brand-400 font-mono text-sm leading-relaxed">RULE_ID = "AZ-STOR-XXX"\nRULE_NAME = "My New Rule"\nSEVERITY = "HIGH"\nCATEGORY = "Storage"\n\ndef scan(azure_client, sub_id):\n    # Your discovery logic here\n    return findings</pre>
                </div>

                <h4 class="text-xl font-bold mb-6 dark:text-white">Testing & Validation</h4>
                <div class="relative rounded-2xl overflow-hidden bg-slate-900 shadow-2xl border border-slate-800">
                    <div class="flex items-center px-4 py-3 bg-slate-800/50 border-b border-slate-800">
                        <div class="flex space-x-2">
                            <div class="w-2.5 h-2.5 rounded-full bg-[#ff5f56]"></div>
                            <div class="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]"></div>
                            <div class="w-2.5 h-2.5 rounded-full bg-[#27c93f]"></div>
                        </div>
                        <div class="mx-auto text-[10px] text-slate-500 font-mono tracking-widest uppercase">bash : test</div>
                    </div>
                    <pre class="p-8 text-slate-300 font-mono text-sm">python -c "from scanner.rules import my_rule; print(my_rule.scan(client, sub))"</pre>
                </div>
            `
        },
        {
            id: "api-reference",
            title: "API Reference",
            content: `
                <h3 class="text-3xl font-bold mb-8 text-slate-900 dark:text-white">REST API Surface</h3>
                <p class="mb-4 text-slate-600 dark:text-slate-400 text-lg">Standardized endpoints for security orchestration and automation.</p>
                <p class="mb-10 text-slate-500 dark:text-slate-500 text-sm">Base URL: <span class="font-mono text-brand-500">https://openshield-api.onrender.com</span> &nbsp;&mdash;&nbsp; All GET endpoints are public. POST endpoints require a JWT Bearer token.</p>

                <div class="bg-white dark:bg-white/[0.02] border border-slate-200 dark:border-white/10 rounded-[2.5rem] shadow-xl overflow-hidden backdrop-blur-xl">
                    <table class="w-full text-left text-sm border-collapse">
                        <thead>
                            <tr class="bg-slate-50 dark:bg-white/5">
                                <th class="px-8 py-5 font-bold uppercase tracking-wider text-slate-500">Endpoint</th>
                                <th class="px-8 py-5 font-bold uppercase tracking-wider text-slate-500">Method</th>
                                <th class="px-8 py-5 font-bold uppercase tracking-wider text-slate-500">Description</th>
                            </tr>
                        </thead>
                        <tbody class="text-slate-600 dark:text-slate-400">
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/health</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-emerald-500/10 text-emerald-500 rounded text-xs font-bold">GET</span></td>
                                <td class="px-8 py-5">Service health check</td>
                            </tr>
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/findings</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-emerald-500/10 text-emerald-500 rounded text-xs font-bold">GET</span></td>
                                <td class="px-8 py-5">List findings. Filter by <span class="font-mono text-xs">severity</span>, <span class="font-mono text-xs">category</span>, <span class="font-mono text-xs">rule_id</span></td>
                            </tr>
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/findings/{id}/playbook</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-emerald-500/10 text-emerald-500 rounded text-xs font-bold">GET</span></td>
                                <td class="px-8 py-5">Structured remediation playbook for a finding</td>
                            </tr>
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/score</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-emerald-500/10 text-emerald-500 rounded text-xs font-bold">GET</span></td>
                                <td class="px-8 py-5">Overall security posture score (0-100)</td>
                            </tr>
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/score/cve-summary</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-emerald-500/10 text-emerald-500 rounded text-xs font-bold">GET</span></td>
                                <td class="px-8 py-5">CVE counts, max CVSS score, exploit availability</td>
                            </tr>
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/scans</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-emerald-500/10 text-emerald-500 rounded text-xs font-bold">GET</span></td>
                                <td class="px-8 py-5">Scan history ordered by most recent</td>
                            </tr>
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/resources</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-emerald-500/10 text-emerald-500 rounded text-xs font-bold">GET</span></td>
                                <td class="px-8 py-5">Unique Azure resources derived from latest scan</td>
                            </tr>
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/prioritization</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-emerald-500/10 text-emerald-500 rounded text-xs font-bold">GET</span></td>
                                <td class="px-8 py-5">Risk-ranked remediation matrix and action items</td>
                            </tr>
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/drift</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-emerald-500/10 text-emerald-500 rounded text-xs font-bold">GET</span></td>
                                <td class="px-8 py-5">Configuration changes between the last two scans</td>
                            </tr>
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/compliance/{fw}</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-emerald-500/10 text-emerald-500 rounded text-xs font-bold">GET</span></td>
                                <td class="px-8 py-5">Framework posture — <span class="font-mono text-xs">cis | nist | iso27001 | soc2</span></td>
                            </tr>
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/scans/trigger</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-blue-500/10 text-blue-500 rounded text-xs font-bold">POST</span></td>
                                <td class="px-8 py-5">Trigger a scan. Body: <span class="font-mono text-xs">{"subscription_id": "..."}</span></td>
                            </tr>
                            <tr class="border-b border-slate-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/ai/ask</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-blue-500/10 text-blue-500 rounded text-xs font-bold">POST</span></td>
                                <td class="px-8 py-5">RAG-grounded Q&A. Providers: anthropic, groq, gemini</td>
                            </tr>
                            <tr class="hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                <td class="px-8 py-5 font-mono text-brand-500">/api/ai/prioritise</td>
                                <td class="px-8 py-5"><span class="px-2 py-1 bg-blue-500/10 text-blue-500 rounded text-xs font-bold">POST</span></td>
                                <td class="px-8 py-5">AI-ranked findings by real-world exploitability</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            `
        }
    ],
    releases: [
        {
            version: "v0.2.0",
            date: "June 2026",
            type: "major",
            title: "Live Data Wiring & Dashboard",
            notes: [
                "Full React security dashboard — 7 pages: Monitor, Discover, Prioritize, Scan, Comply, Drift, AI",
                "Live backend integration: all GET endpoints public, real PostgreSQL data replaces mock stubs",
                "SOC 2 Type II compliance framework added alongside CIS, NIST, ISO 27001",
                "4 new REST endpoints: /api/resources, /api/prioritization, /api/drift, /api/findings/:id/playbook",
                "Score and findings scoped to latest scan — eliminates stale aggregate counts",
                "CVE enrichment via NVD API: cve_references, cvss_score, exploit_available on every finding",
                "AI layer: chat, executive summary, CVE analysis — bring your own Anthropic/Groq/Gemini key",
                "Configuration drift detection comparing consecutive scans",
                "Project website with docs, rules gallery, roadmap, releases, blog, and playground",
                "CORS fixed to cover all routes including /health for Vercel → Render connectivity"
            ],
            github: "https://github.com/openshield-org/openshield/releases/tag/v0.2.0"
        },
        {
            version: "v0.1.0",
            date: "2025",
            type: "major",
            title: "Initial Release",
            notes: [
                "Flask REST API with JWT authentication and CORS",
                "Scanner engine with 20 Azure misconfiguration rules across Storage, Network, Identity, Database, Compute, and Key Vault",
                "Compliance framework mappings for CIS Azure Benchmark, NIST CSF, ISO 27001, and SOC 2",
                "36 Azure CLI remediation playbooks — one per scanner rule",
                "PostgreSQL persistence for scan history and findings",
                "Microsoft Sentinel integration via Log Analytics custom table and KQL analytics rules",
                "GitHub Actions CI pipeline with 7 automated checks"
            ],
            github: "https://github.com/openshield-org/openshield/releases/tag/v0.1.0"
        }
    ],

    faq: [
        {
            question: "Is OpenShield free to use?",
            answer: "Yes. OpenShield is fully open source under the MIT licence. You can use, modify, and distribute it at no cost, including in commercial environments."
        },
        {
            question: "What cloud providers are supported?",
            answer: "Azure is the current target. Multi-cloud support for AWS and GCP is on the roadmap. The rule engine is designed to be provider-agnostic at the orchestration level, so adding a new provider requires only a new SDK client wrapper."
        },
        {
            question: "What Azure permissions does the scanner need?",
            answer: "The scanner requires read-only access. A service principal with the built-in Reader role at subscription scope is sufficient for all 20 current rules. No write permissions are used."
        },
        {
            question: "Can I write my own security rules?",
            answer: "Yes. Drop a .py file into scanner/rules/ following the rule template in the Docs section. The engine dynamically imports any file that exposes a scan() function. No changes to the core orchestrator are required."
        },
        {
            question: "Where is scan data stored?",
            answer: "All findings and scan history are stored in your own PostgreSQL database. Nothing is transmitted to external services unless you enable CVE enrichment, which queries the public NVD API by rule keyword."
        },
        {
            question: "Does the AI layer send my findings to third parties?",
            answer: "Only when you explicitly trigger an AI request and provide your own provider API key. Your key and findings are sent directly from your browser to the provider you choose (Anthropic, Groq, or Gemini). The OpenShield backend never stores or logs your key."
        },
        {
            question: "How do I try the live dashboard?",
            answer: "The project website is at openshield-website.vercel.app. The security dashboard is at openshield-gules.vercel.app and connects to the live backend at openshield-api.onrender.com."
        },
        {
            question: "How do I contribute?",
            answer: "The highest-value contributions are new scanner rules and compliance mappings. See CONTRIBUTING.md in the repository for a step-by-step guide. A new rule with a matching playbook and compliance mapping can be submitted in a single PR in under 30 minutes."
        }
    ],

    terminal: [
        {
            command: "git clone https://github.com/openshield-org/openshield.git",
            output: ["Cloning into 'openshield'...", "Receiving objects: 100% (452/452), 2.1 MB done."]
        },
        {
            command: "curl https://openshield-api.onrender.com/api/score",
            output: ["62"]
        },
        {
            command: "curl https://openshield-api.onrender.com/api/findings | python -m json.tool | head -20",
            output: ["{ \"count\": 10, \"findings\": [", "  { \"rule_id\": \"AZ-STOR-001\", \"severity\": \"HIGH\", ... }", "  { \"rule_id\": \"AZ-NET-001\", \"severity\": \"HIGH\", ... }", "  ...8 more findings", "]}"]
        }
    ]
};
