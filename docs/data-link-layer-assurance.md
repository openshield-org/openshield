# Azure Data Link Layer Assurance

OpenShield treats Azure OSI Layer 2 as a shared responsibility boundary. Microsoft owns the virtual switching fabric, forwarding tables, broadcast behavior, and tenant-isolation internals. Azure customers cannot inspect those systems, so OpenShield records provider assurance and platform enforcement without creating findings or changing the tenant security score.

ExpressRoute Direct is different because Azure exposes customer-controlled Ethernet link configuration through the management API. OpenShield checks enabled links for MACsec and checks ports of 40 Gbps or greater for an XPN MACsec cipher. A subscription with no ExpressRoute Direct ports is not applicable. An Azure API or permission failure is indeterminate and never creates a finding.

The customer-actionable checks use the dedicated Data Link identifiers `AZ-DL-001` and `AZ-DL-002`. The `AZ-DL` namespace distinguishes these Layer 2 controls from the mixed-layer rules historically stored under `AZ-NET`.

## Coverage

The closed catalog covers both IEEE 802 Data Link sublayers, LLC and MAC, and all 19 functional domains required by issue #241. Each domain records Azure applicability, responsibility, observability, evidence, and one of the supported verification states.

`GET /api/assurance/data-link-layer` requires JWT authentication. It returns the layer and scope, responsibility boundary, domain and sublayer coverage, provider and platform states, automated-control applicability, evidence review dates, source links, and explicit limitations. Catalog coverage and evidence freshness are separate measurements.

The endpoint does not claim live access to Microsoft switches, VLANs, forwarding tables, or fabric internals. It requires no paid OpenShield service or external runtime API.

## Secret handling

The checks test only whether a MACsec configuration exists and which cipher is selected. They never read, store, log, or return CAK or CKN secret values. Findings contain only the port identity, link name, bandwidth, and non-secret cipher name.
