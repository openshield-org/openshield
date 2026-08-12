# Azure Network Layer assurance

OpenShield's authenticated `GET /api/assurance/network-layer` endpoint returns a closed OSI Layer 3 catalog for Azure public-cloud networking. It covers all 20 required addressing, routing, transit, isolation, IP-boundary protection, and diagnostic domains and reports catalog completeness separately from evidence freshness.

## Responsibility boundary

Customers control exposed address spaces, subnets, routes, peerings, gateways, public IP associations, and supported diagnostics. Microsoft owns the Azure fabric, underlying forwarding implementation, tenant isolation, physical packet handling, and system internals that subscriptions cannot inspect. Provider-owned domains are documented but never create findings or change the tenant score.

The catalog classifies every `AZ-NET-001` through `AZ-NET-015` rule by actual behavior. Port-specific NSG rules remain Layer 4, the public DNS rule remains Layer 7, and ExpressRoute Direct MACsec rules remain Layer 2. Cross-layer rules only reference Layer 3 domains when part of their behavior genuinely covers IP addressing, routing, or segmentation.

## Automation limits

The report cross-references existing authoritative management-plane checks. It does not add speculative findings for route intent, address overlap, next-hop correctness, MTU, ICMP reachability, BGP advertisement, or Microsoft anti-spoofing internals. Those conditions require architecture intent, selected endpoints, packet tests, or provider evidence that the scanner does not possess.

Empty relevant inventory is `NOT_APPLICABLE`; Azure API or permission failure is `INDETERMINATE`. Neither state creates a finding. The endpoint is documentation-backed assurance, not packet capture, live traffic inspection, or access to Microsoft forwarding tables.
