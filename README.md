# OpenAssetWatch

**OpenAssetWatch** is an open-source asset intelligence platform designed to help families, home labs, small teams, and future enterprise users understand what is on their network, what changed, and what should be fixed first.

The long-term vision is to provide Armis-style visibility using open-source-friendly components: local collectors, network discovery, passive sensing, asset enrichment, risk scoring, AI-assisted guidance, and future Splunk CIM-compatible export.

> Status: Early MVP / active development

---

## What OpenAssetWatch Is Building

OpenAssetWatch is being built to answer simple but important questions:

* What devices are on my network?
* Which devices are new or unknown?
* Which devices look like IoT, infrastructure, servers, or workstations?
* Which devices expose risky services?
* Which assets are missing security tooling or vulnerability coverage?
* Which risks should I focus on first?
* How can this information be explained clearly to non-technical users?

The platform starts with safe local discovery and grows into a broader asset risk intelligence platform.

---

## Current MVP Scope

The current MVP focuses on:

* Self-hosted Control Tower foundation
* FastAPI backend API
* PostgreSQL persistence through Docker Compose
* Static web dashboard foundation
* Site/project model
* Agent and future sensor enrollment model
* Agent check-in and local inventory ingestion endpoints
* Basic asset normalization and evidence counts
* Standalone collector framework
* Device, network, and hybrid collector modes
* Local ARP/neighbor discovery
* Safe filtering of multicast, broadcast, and non-host network entries
* Architecture documentation for future AI, IoT/OT, vulnerability, ITSM, identity, PAM, cloud, and Splunk integrations

---

## High-Level Architecture

```text
Local Device / Network
        |
        v
OpenAssetWatch Collector
        |
        v
OpenAssetWatch Backend API
        |
        v
PostgreSQL / Redis
        |
        v
Control Tower Dashboard / Risk Engine / AI Advisor / Integrations
```

### Collector Modes

OpenAssetWatch collectors are designed to run in different modes:

| Mode      | Purpose                                                         |
| --------- | --------------------------------------------------------------- |
| `device`  | Collects information about the device running the collector     |
| `network` | Discovers nearby devices using local network visibility         |
| `hybrid`  | Combines device and network collection                          |
| `sensor`  | Future passive network sensor mode for deeper IoT/OT visibility |

---

## Repository Structure

```text
openassetwatch/
├── backend/                  # FastAPI backend service
├── collector/                # Standalone collector code
├── database/                 # Initial database schema
├── deployment/               # Deployment-related files
├── docs/                     # Architecture and roadmap documentation
├── frontend/                 # Future web UI
├── .github/                  # GitHub Actions workflows
├── docker-compose.yml        # Local development stack
├── .env.example              # Environment variable example
└── README.md
```

---

## Local Development

### Start the backend stack

```bash
docker compose up -d
```

### Check backend health

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{
  "status": "healthy",
  "service": "openassetwatch-control-tower",
  "version": "0.1.0"
}
```

### Open the Control Tower dashboard

```text
http://localhost:8080
```

The local stack binds API, web, PostgreSQL, and Redis ports to localhost by
default. See [docs/CONTROL_TOWER_DEPLOYMENT.md](docs/CONTROL_TOWER_DEPLOYMENT.md)
for startup steps, API endpoints, database tables, and limitations.

---

## Running the Collector Locally

From the repository root:

```bash
PYTHONPATH=collector python -m openassetwatch_collector --mode device --pretty
```

```bash
PYTHONPATH=collector python -m openassetwatch_collector --mode network --pretty
```

```bash
PYTHONPATH=collector python -m openassetwatch_collector --mode hybrid --pretty
```

### Device Mode

Device mode reports information about the machine running the collector, such as:

* Hostname
* FQDN
* Platform
* OS release
* Architecture
* Primary IP address
* MAC address

### Network Mode

Network mode uses local network visibility to discover nearby devices. Current discovery is intentionally conservative and focuses on safe ARP/neighbor data.

The collector filters out entries such as:

* Multicast addresses
* Broadcast addresses
* Loopback addresses
* Invalid IP addresses
* Non-host MAC addresses

### Hybrid Mode

Hybrid mode combines device inventory and local network discovery into one payload.

---

## Backend API

Current and planned backend endpoints include:

| Endpoint | Status | Purpose |
| --- | --- | --- |
| `GET /health` | Available | Control Tower health and version |
| `GET /api/v1/sites` | Available | List sites/projects |
| `POST /api/v1/sites` | Available | Create or update a site/project |
| `GET /api/v1/agents` | Available | List endpoint agents and future sensors |
| `POST /api/v1/agents/enrollments` | Available | Create or update agent/sensor enrollment records |
| `POST /api/v1/agents/check-in` | Available | Agent health and identity check-in |
| `POST /api/v1/collections/local-inventory` | Available | Go agent local inventory ingestion |
| `GET /api/v1/control-tower/summary` | Available | Dashboard counts |
| `GET /api/v1/control-tower/assets` | Available | Normalized Control Tower assets |
| `GET /api/v1/releases/agent` | Available | Agent release metadata placeholder |
| `POST /api/v1/collectors/checkin` | Available | Legacy Python collector heartbeat/check-in |
| `POST /api/v1/collectors/inventory` | Available | Legacy Python collector inventory upload |

---

## Future Roadmap

OpenAssetWatch is being designed as more than a basic network scanner. The long-term roadmap includes several major tracks.

### 1. Collector Packaging

Future collector packaging may include:

* Python package install
* Standalone executable builds
* Windows service installer
  * Agent native Windows service and MSI deployment details:
    [docs/AGENT_WINDOWS_DEPLOYMENT.md](docs/AGENT_WINDOWS_DEPLOYMENT.md)
* Linux systemd installer
  * Agent Linux DEB/RPM/TAR.GZ package source and release pipeline details:
    [docs/AGENT_INSTALLATION.md](docs/AGENT_INSTALLATION.md) and
    [docs/RELEASE_PIPELINE.md](docs/RELEASE_PIPELINE.md)
* macOS launchd PKG installer
  * Agent macOS LaunchDaemon and PKG deployment details:
    [docs/AGENT_MACOS_DEPLOYMENT.md](docs/AGENT_MACOS_DEPLOYMENT.md)
* Raspberry Pi / ARM support
* Docker-based sensor deployment

### 2. Backend Ingestion

Future backend work includes:

* Collector registration
* Collector heartbeat/check-in
* Inventory upload
* Asset normalization
* Asset history
* Risk findings
* API key or enrollment-token authentication

### 3. Web Dashboard

Future dashboard capabilities may include:

* Asset inventory
* Collector health
* New device detection
* Risk findings
* Device timeline
* Network visibility
* Remediation priorities

### 4. AI Advisor

The AI Advisor is planned as an advisory layer that runs after data collection, normalization, and rule-based scoring.

The AI Advisor may help users:

* Understand what changed
* Prioritize what to fix first
* Explain risk in plain language
* Summarize asset exposure
* Recommend segmentation or remediation steps
* Identify gaps across discovery, vulnerability, identity, and ITSM data

AI should be advisory only. It should not automatically make network, firewall, cloud, identity, PAM, or endpoint changes.

Future deployment options may include:

* Local/self-hosted AI using Qwen, Ollama, llama.cpp, or similar tools
* Cloud/VPS-hosted AI for SaaS-like deployments
* Optional external LLM providers

### 5. IoT/OT and Network Sensor Roadmap

Future OpenAssetWatch network sensors may support passive visibility for:

* Smart home IoT devices
* Cameras
* Printers
* Smart TVs
* Voice assistants
* Appliances
* Routers and switches
* Firewalls and access points
* Embedded Linux devices
* Raspberry Pi and lab systems
* OT-like lab environments

Future passive fingerprinting sources may include:

* DHCP metadata
* MAC OUI/vendor data
* mDNS/Bonjour
* SSDP/UPnP
* NetBIOS
* DNS queries
* TLS SNI
* HTTP headers
* Observed protocols
* Communication patterns
* Zeek metadata
* Suricata metadata

OpenAssetWatch should remain passive-first and avoid aggressive scanning or exploit-style checks by default.

### 6. Vulnerability Scanner Enrichment

Future vulnerability enrichment may include integrations with:

* Qualys
* Tenable / Nessus
* Rapid7 InsightVM / Nexpose
* Greenbone / OpenVAS
* Microsoft Defender Vulnerability Management
* Wiz or other cloud vulnerability platforms

The goal is to correlate discovered assets with vulnerability context, exploitability, exposure, and remediation status.

### 7. ITSM and CMDB Enrichment

Future ITSM and CMDB enrichment may include integrations with:

* ServiceNow
* Jira Service Management
* Freshservice
* BMC Helix
* Other CMDB or asset inventory systems

The goal is to connect risk findings to ownership, support groups, business services, criticality, incidents, problems, and change records.

### 8. Identity and Directory Enrichment

Future identity enrichment may include:

* Microsoft Active Directory
* Microsoft Entra ID
* LDAP directories
* Okta
* Duo
* Google Workspace
* Local Windows/Linux account inventory

The goal is to connect assets to users, ownership, directory status, MFA posture, compliance state, and privileged group membership.

### 9. PAM and Privileged Account Enrichment

Future privileged account enrichment may include:

* CyberArk
* BeyondTrust
* Delinea / Thycotic
* HashiCorp Vault
* Active Directory privileged groups
* Microsoft Entra privileged roles
* Microsoft Entra PIM

OpenAssetWatch must never collect, store, display, transmit, or export actual passwords, hashes, private keys, tokens, API secrets, or secret values.

Only safe metadata and posture indicators should be collected, such as:

* Vaulted status
* Password age
* Last rotation date
* Account owner
* Account enabled status
* MFA requirement
* Associated asset
* Finding status

### 10. Cloud Provider Enrichment

Future cloud enrichment may include:

* AWS
* Microsoft Azure
* Google Cloud Platform
* Oracle Cloud, optional later

Future use cases may include:

* Public exposure detection
* Security group risk
* Cloud asset correlation
* Owner tag validation
* IAM role context
* Cloud vulnerability and threat finding enrichment

### 11. Splunk TA and CIM Compatibility

A future Splunk Technology Add-on may be created as:

```text
TA-openassetwatch
```

The Splunk TA should:

* Ingest OpenAssetWatch JSON events
* Define sourcetypes
* Provide field extractions
* Provide eventtypes and tags
* Map OpenAssetWatch fields to Splunk CIM-compatible fields where appropriate
* Keep Splunk-specific naming in the TA instead of forcing it into the OpenAssetWatch core schema

Potential future sourcetypes:

```text
openassetwatch:asset
openassetwatch:collector
openassetwatch:finding
openassetwatch:network
openassetwatch:service
openassetwatch:vulnerability
openassetwatch:identity
openassetwatch:pam
openassetwatch:cloud
openassetwatch:itsm
openassetwatch:security_event
openassetwatch:ai_advisor
```

---

## Design Principles

OpenAssetWatch follows these core principles:

* Safe discovery first
* Passive-first where possible
* Vendor-neutral core schema
* Evidence-backed findings
* Confidence levels for inferred data
* No exploit checks by default
* No automatic remediation without user approval
* No secrets stored in code or configuration
* Local-first and privacy-conscious design
* Cloud/SaaS deployment options later

---

## Security and Privacy

OpenAssetWatch is intended to collect asset and posture metadata, not sensitive secrets.

The project should not collect or store:

* Passwords
* Password hashes
* Private keys
* API secrets
* Session tokens
* OAuth tokens
* Vault credentials
* Secret values

Future integrations should use least-privilege access and should be disabled by default until explicitly configured.

---

## Development Status

OpenAssetWatch is currently in early MVP development.

Current completed work includes:

* Initial repository scaffold
* FastAPI backend foundation
* Docker Compose local stack
* PostgreSQL and Redis services
* Collector modes: device, network, and hybrid
* Platform and capability detection
* Local network ARP/neighbor discovery
* Filtering for non-host network entries
* Collector CI workflow roadmap
* Architecture roadmap documentation

---

## Contributing

This project is still early, so contribution guidance will evolve over time.

Future contribution areas may include:

* Collector development
* Backend API development
* Database schema design
* Frontend/dashboard design
* Documentation
* Testing
* Packaging and installers
* Integrations
* Splunk TA development
* AI Advisor design

---

## License

OpenAssetWatch is licensed under the Apache License, Version 2.0. See LICENSE for details.
