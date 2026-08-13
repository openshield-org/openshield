# Physical Layer Assurance

OpenShield reports Azure public-cloud OSI Layer 1 coverage through provider assurance rather than tenant-side hardware scanning. Microsoft owns and operates the physical datacenter network for Azure IaaS, PaaS, and SaaS. Azure tenants cannot inspect its cables, optics, radios, racks, physical access records, power, or cooling systems.

## Coverage definition

The bundled catalog is closed and validated at runtime and in tests. It contains:

- 21 physical domains covering generic OSI Layer 1 functions, Ethernet and wireless PHY functions, network resilience, facility protection, environmental systems, and equipment lifecycle controls.
- Eight generic and IEEE PHY profiles: generic Layer 1, PLCP, PCS, FEC, PMA, PMD, auto-negotiation and link training, and MDI.
- Microsoft SOC controls PE-1 through PE-8.
- All ISO/IEC 27001:2013 A.11 controls, A.11.1.1 through A.11.1.6 and A.11.2.1 through A.11.2.9.

Catalog coverage and evidence freshness are separate measurements. A control remains mapped when evidence reaches its review date, but its status changes from `PROVIDER_ATTESTED` to `REVIEW_DUE`. OpenShield never converts provider evidence into a technical scan pass or failure and does not include it in the tenant security score.

## API

`GET /api/assurance/physical-layer` requires the same JWT authentication as other API routes. The response includes:

- scope and shared-responsibility boundaries;
- catalog and evidence coverage summaries;
- all physical domains and their control and sublayer mappings;
- all generic and IEEE physical sublayers;
- all baseline controls with expanded Microsoft evidence;
- explicit limitations preventing the report from being interpreted as live hardware inspection or certification.

The endpoint performs no external request and requires no paid service. Evidence metadata is stored in `compliance/assurance/physical_layer.json`, making assessments deterministic and reviewable in pull requests.

## Maintaining evidence

When Microsoft documentation changes, update the affected evidence entry's URL, `reviewed_at`, and `review_due_at` dates. Do not remove a domain, sublayer, PE control, or ISO A.11 control. The validator intentionally rejects incomplete catalogs, unknown references, insecure evidence URLs, non-Microsoft responsibility assignments, and claims of automated physical verification.
