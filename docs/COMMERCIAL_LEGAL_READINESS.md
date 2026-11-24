# Commercial legal readiness

Use this checklist for a specific release, distribution channel, deployment
model, and jurisdiction. Engineering supplies the evidence and verifies the
controls. Items marked **Requires legal counsel** need a qualified legal
determination before the relevant use or commitment.

| Area | Engineering evidence and future work | Requires legal counsel |
| --- | --- | --- |
| Software distribution | Freeze each package and image digest. Close the [distribution inventory](DISTRIBUTION_LICENSE_INVENTORY.md). Deliver applicable license texts, attribution and notices, source or source offers, and relinking materials. Verify artifact SBOMs, checksums, signing, and provenance. | Interpret unclear licenses and exceptions. Confirm the scope and form of source, offer, and attribution obligations for specific releases. |
| Privacy and data governance | Maintain the [data-handling disclosure](DATA_HANDLING_AND_PRIVACY.md). Define retention and backup expiry, deletion and return, request intake and verification, telemetry and external AI disclosures, processor inventory, and data locations. Test deletion against derived and historical records and backup restoration. | Determine applicability of domestic and international privacy statutes, cross-border transfer requirements, legal Privacy Policy, notices and consents, request rights, and processor obligations. |
| Commercial service | Define offered deployment modes, support boundaries, acceptable-use controls, measurement and incident processes, and any proposed service levels. | Draft or review Terms of Service, support terms, acceptable-use terms, warranties, indemnification, limitations of liability, and enforceability. |
| Enterprise and customer contracts | Document security controls, subprocessors, data location, deletion and return, and feasible breach-notification and service commitments. Align contracts with tested capabilities. | Determine when a DPA and transfer terms are required. Review security exhibits, subprocessor terms, breach notification, data-location commitments, deletion and return obligations, and contract enforceability. |
| Intellectual property | Preserve contributor sign-offs and provenance. Verify rights for third-party content, branding, and artifacts. Escalate disputes and any clarification of contributor terms. | Trademark clearance and registration, patent freedom-to-operate, employment and contributor ownership disputes, and interpretation of ambiguous license or contribution rights. |
| Cybersecurity product and international distribution | Document authorized monitoring, customer responsibility for scope, and the product boundary that excludes offensive capabilities. Inventory encryption, hosted functions, components, markets, and distribution channels for review. | Assess export controls, sanctions, encryption controls, cross-border restrictions, and jurisdiction-specific monitoring terms before international commercial distribution. |

The [readiness audit](LEGAL_READINESS_AUDIT.md) records current engineering
evidence separately from future commercial work. A documented control or
successful test establishes only the observed behavior.
