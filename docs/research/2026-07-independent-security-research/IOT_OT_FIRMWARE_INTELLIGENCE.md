# IoT, OT, Firmware, and Appliance Intelligence

## Status

Independent research input. The second-pass adversarial audit controls factual corrections and source grading where it conflicts with the first-pass study.

## Core conclusion

Reliable IoT, OT, firmware, and appliance intelligence is possible only when the system:

- treats passive observation as the default;
- places active interrogation behind deterministic, auditable safety gates;
- preserves every fingerprint as a hypothesis with provenance and confidence;
- separates product identification from vulnerability confirmation;
- consumes multiple advisory and lifecycle sources rather than relying on NVD enrichment alone; and
- performs a license and redistribution review before incorporating third-party fingerprint data.

## Passive-first safety boundary

NIST OT guidance places active scanning in a higher-risk category because active requests can destabilize devices or interfere with process state. The audited source correction places this material in NIST SP 800-82 Rev. 3 Appendix E.2.2–E.2.3 rather than Section 6.2.1.

The safe baseline is:

- SPAN, mirror, TAP, sensor, and log-based observation;
- protocol parsing without packet injection;
- no write or control function codes for identification;
- no model-generated probes;
- explicit user policy before any active behavior;
- vendor and model validation;
- testbed validation where possible;
- OT operator or safety-engineer approval; and
- independent logging of every active attempt.

Active behavior must be enforced through deterministic network and tool controls, not through a prompt telling an agent to remain passive.

## Passive evidence sources

### Consumer and enterprise device signals

- DHCP option order, vendor class, client identifier, and hostname.
- mDNS and DNS-SD service names.
- SSDP and UPnP descriptors.
- DNS destination behavior, subject to DoH/DoT visibility limits.
- TLS ClientHello and ServerHello fingerprints.
- JA4-family fingerprints, with license distinctions.
- HTTP headers, server titles, and device web interfaces.
- Certificates and certificate-chain characteristics.
- ARP and switch CAM observations.
- MAC/OUI, treated as a component-vendor hint rather than proof of device brand.
- LLDP and CDP.
- SNMP traps or pre-authorized read-only queries.
- NetBIOS, SMB, NTP, MQTT, CoAP, AMQP, ONVIF, RTSP, SIP, IPP, and printer-service metadata.
- Longitudinal traffic timing and protocol behavior.

### Industrial protocol evidence

Protocols such as Modbus, DNP3, BACnet, EtherNet/IP, S7comm, PROFINET, IEC 60870-5-104, IEC 61850, OPC UA, and vendor-specific discovery can reveal device family, role, firmware, and topology.

The identification boundary is observation. A write, control, state-changing, or process-impacting request is not an identification function and is prohibited by default.

## Signal limitations

- DHCP and TLS fingerprints often identify stack or device class rather than an exact instance.
- OUI frequently identifies a chipset or module manufacturer, not the consumer-facing brand.
- mDNS, SSDP, banners, and HTTP content are spoofable and vendor-inconsistent.
- DNS evidence disappears under encrypted DNS and proxying.
- Reverse proxies and shared software stacks create false matches.
- Encrypted traffic reduces behavioral visibility.
- MAC randomization weakens longitudinal correlation.
- Silent devices remain invisible to purely passive approaches.
- Lab classification accuracy does not prove field-level model or firmware accuracy.

## Asset-class guidance

### Routers, modems, access points, firewalls, and switches

Useful signals include LLDP/CDP, SNMP, UPnP, web interfaces, certificates, OUI, and DHCP. ISP customization, OEM rebadging, and hardware revisions complicate firmware matching.

### NAS, printers, cameras, and doorbells

mDNS, SSDP, ONVIF, RTSP, IPP, SNMP, HTTP, and certificates can provide strong product-family evidence. Printers and cameras can be fragile under aggressive probing, so passive observation remains preferred.

### Smart TVs, streaming devices, consoles, speakers, and hubs

DHCP, mDNS/DIAL, DNS destinations, TLS/JA4, and behavior often identify device class. Exact model and firmware remain harder.

### Building automation and physical security

BACnet, KNX, LonWorks, ONVIF, and vendor protocols expose useful metadata but require strict passive and safety boundaries.

### PLCs, RTUs, HMIs, drives, gateways, and safety systems

Use passive industrial-protocol and topology evidence. Active probing must require vendor/model validation and operational approval.

### Medical and health-adjacent devices

Use passive identification and authoritative advisories. Current FDA guidance must be re-verified before publication; the February 3, 2026 Quality Management System revision superseded the June 27, 2025 version.

## Firmware identity

Potential firmware evidence includes:

- protocol and service version strings;
- web interface metadata;
- authenticated SNMP values;
- UPnP and ONVIF descriptors;
- update metadata;
- vendor APIs;
- device certificates;
- boot or build information;
- package manifests and SBOMs;
- public firmware images;
- binary headers, build IDs, strings, and extracted packages; and
- collector-observed installed versions.

Firmware identity must preserve:

- raw version text;
- normalized interpretation;
- hardware revision;
- region or carrier variant;
- OEM or ODM relationships;
- rebadged product relationships;
- shared firmware families;
- confidence;
- source and timestamp; and
- unresolved alternatives.

A missing version must remain unknown. It must not be fabricated from the newest vendor release or inferred as patched.

## Product and vendor normalization

The research identifies product normalization as a major unsolved problem. Important complications include:

- acquisitions and brand changes;
- OEM/ODM manufacturing;
- white-label hardware;
- common firmware across several brands;
- hardware revision changes under one model name;
- ISP-custom firmware;
- regional variants;
- open-source firmware forks;
- reused model numbers; and
- identifiers that refer to components rather than the complete device.

Potential normalizers include:

- CPE for vulnerability correlation, with acknowledged hardware limitations;
- package URL for software components;
- SPDX and CycloneDX SBOMs;
- SWID/CoSWID where available;
- GS1 identifiers for hardware where available;
- FCC IDs and regulatory filings;
- USB and PCI IDs;
- IEEE address assignments;
- Bluetooth assigned numbers; and
- curated vendor, model, revision, and rebadge mappings.

## Advisory and lifecycle sources

A multi-source strategy should consider:

- Official CVE JSON records.
- NVD as one source rather than a universal enrichment authority.
- CISA KEV.
- FIRST EPSS.
- CISA ICS and ICS Medical Advisories.
- Vendor Product Security Incident Response Team advisories.
- Siemens ProductCERT for updates beyond CISA's initial Siemens advisory publication.
- OSV and GitHub advisories for open-source firmware components.
- National CERT and EU sources.
- CSAF 2.0 advisories.
- VEX statements.
- Vendor EOL and EOS pages.
- endoflife.date as a convenience source, not an authoritative universal hardware catalog.
- Product recalls and public safety notices.

The NVD policy shift and CPE coverage gaps particularly affect firmware and hardware correlation. Lack of CPE enrichment must not be treated as proof that a vulnerability is irrelevant.

## Open fingerprint projects and status

### Stronger reusable candidates

- **Recog** — BSD-2-Clause; maintained; HTTP, SNMP, certificate, and banner fingerprints.
- **OSV schema and data** — open machine-readable package-vulnerability foundation.
- **USB and PCI ID repositories** — dual GPL/BSD licensing options.
- **ICS Advisory Project** — ODbL; machine-readable CISA ICS advisory data.
- **p0f** — LGPL, but signatures are substantially stale and should be treated as legacy research input.
- **JA4 TLS client method** — BSD-3-Clause.

### Restricted, ambiguous, or commercial sources

- Nmap fingerprint data under NPSL requires careful legal review.
- Non-TLS JA4+ methods use the FoxIO license and may restrict monetized use.
- Fingerbank's current database and API are commercial, despite historic open data.
- Wappalyzer's current primary rules are closed-source; community forks require separate review.
- Censys and Shodan data are proprietary and not redistributable.
- IEEE address registry data is public but should receive a formal redistribution review.
- Bluetooth SIG assigned numbers are proprietary.

### Retired or unsafe references

GRASSMARLIN is end-of-life, with its last release in 2017. The audit rejected the unsupported claim that it became read-only in April 2023. Its 2026 vulnerability and lack of a fix make it a cautionary example of continuing to depend on abandoned visibility tooling.

## License-control requirement

Every bundled dataset or signature source should have a documented decision covering:

- copyright owner;
- license version;
- redistribution rights;
- attribution;
- share-alike requirements;
- commercial-use restrictions;
- patent or OEM terms;
- update mechanism;
- derived-work implications; and
- whether the data may be included, fetched by the user, referenced remotely, or excluded.

## Community fingerprint corpus

A safe open corpus should require:

- a stable schema;
- passive or active collection method labeling;
- raw evidence references without personal payloads;
- provenance and timestamp;
- contributor identity or signed contribution;
- licensing sign-off;
- peer review;
- source reputation;
- duplicate and conflict detection;
- evidence thresholds;
- quarantine for unverified submissions;
- corrections, supersession, and retractions;
- dispute resolution;
- privacy minimization; and
- an explicit unknown state.

A fingerprint contribution must never become an authoritative vulnerability finding merely because it entered the corpus.

## IoT and OT risk considerations

Important context includes:

- physical and safety consequence;
- availability requirements;
- replacement cost and lifecycle;
- unpatchable and end-of-life devices;
- insecure-by-design plaintext protocols;
- default credentials;
- vendor remote access;
- internet exposure;
- IT/OT conduits;
- lateral movement;
- monitoring gaps;
- warranty and safety certification;
- compensating controls; and
- replacement planning.

CVSS alone frequently misrepresents OT priority. Consequence, exposure, safety, and mission importance must be decision inputs.

## Evaluation

Report separately:

- device-class precision and recall;
- vendor identification accuracy;
- model identification accuracy;
- firmware accuracy;
- vulnerability-correlation precision and recall;
- unknown-device rate;
- passive-only accuracy;
- safe-active uplift;
- encrypted-traffic performance;
- white-label performance;
- MAC-randomization performance;
- false-positive rate;
- field-versus-lab performance; and
- safety incidents caused by discovery.

A claim of zero safety incidents is meaningful only when the denominator, active/passive boundary, logging, and test conditions are disclosed.

## Durable findings

- `PASV-RES-001` — passive-first is the authoritative OT baseline.
- `OT-RES-001` — active scanning of fragile OT requires strict validation and approval.
- `FW-RES-001` — firmware identity must remain multi-hypothesis and provenance-tagged.
- `ADV-RES-001` — NVD enrichment degradation weakens firmware and hardware correlation.
- `IOT-RES-001` — high lab device-type accuracy is not production instance accuracy.
- `LIC-RES-001` — fingerprint and advisory licensing is a primary integration risk.
- `GOV-RES-001` — an openly licensed, signed, provenance-preserving fingerprint corpus is a high-value opportunity.
