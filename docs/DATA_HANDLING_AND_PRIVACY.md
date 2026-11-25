# Data handling and privacy

This engineering disclosure describes the self-hosted implementation and its
optional data flows. See [commercial legal readiness](COMMERCIAL_LEGAL_READINESS.md)
for counsel review and customer-facing policy work.

## Default and optional flows

- A fresh hub receives data when an operator enrolls or configures a spoke, uses
  an ingestion route, or runs the optional synthetic demo. The reference
  Compose deployment uses a local PostgreSQL volume and loopback-bound
  published ports. Operators choose the actual host, storage, and network.
- The one-shot Python collector emits normalized local inventory to stdout.
  Optional check-ins, uploads, scheduled cycles, and policy polling connect to
  the configured backend. Device mode collects local device and software
  facts. Network and hybrid modes can read OS neighbor tables.
- The agent collects host, network, and installed-software observations using
  platform-local sources. A local run can write an inventory JSON file under
  agent state. A configured check-in or submission sends scoped data to the
  chosen hub. Installers can configure persistent service or timer behavior.
- The sensor defaults to synthetic capture in its base config. Live Linux
  capture is an explicit deployment mode. Frames are processed in memory into
  bounded metadata. The sensor sends normalized batches and health, keeps a
  bounded local queue, and does not write or upload raw packet captures. Replay
  uses an operator-supplied local input file. The original replay file remains
  an operator-managed artifact.
- The Advisor defaults to its deterministic demo mode and uses bounded,
  read-only hub tools. A configured local inference endpoint receives the
  question and selected evidence across that endpoint's trust boundary.
  Hosted requests require explicit external enablement, a configured provider,
  and credentials. A configured hosted call sends the question, selected
  structured evidence, and request metadata to that provider. A local failure
  does not trigger a hosted call. Provider-side retention and deletion depend
  on the operator's configuration and provider terms.
- Operator-triggered advisory synchronization retrieves reviewed public feed
  artifacts from configured endpoints. It receives external data and exposes
  ordinary connection metadata to the endpoint. The signed publication
  pipeline works with public advisory sources and publishes reviewed advisory
  artifacts.
- Opening the built-in interactive API documentation can cause the browser to
  load framework assets from public endpoints. The endpoints receive normal
  browser request metadata. The Control Tower's first-party dashboard uses
  inline resources and system fonts.

Evidence for these flows includes the
[reference Compose file](../docker-compose.yml), [collector entry point](../collector/openassetwatch_collector/main.py),
[agent entry point](../cmd/oaw-agent/main.go), [sensor configuration](../internal/sensor/config/config.go),
[sensor capture](../internal/sensor/capture/live_linux.go), [sensor runtime](../internal/sensor/runtime/runtime.go),
[Advisor provider routing](../backend/app/ai_advisor.py), and
[feed synchronization](../backend/app/advisory_sync_service.py).

## Data inventory

PostgreSQL means the configured hub database. The reference Compose volume
persists that data across container replacement. **NOT DEFINED** means the
review found no product-wide time limit or erasure workflow for those records.
Schema cascades and revocation are narrower controls. They do not establish
backup erasure or a customer deletion service.

| Data and source | Purpose and authority | Default storage and processing | Retention and deletion | AI visibility and sensitivity |
| --- | --- | --- | --- | --- |
| Site and asset IDs, names, and source identifiers from operator setup and enrolled submissions | Hub assigns or reconciles identities and scopes inventory. Source names and claimed identities remain observations until reconciled. | Hub PostgreSQL and local spoke identity/configuration. | Hub retention and deletion **NOT DEFINED**. Normal uninstall commonly preserves local identity. Explicit purge varies by installer. | Selected site and asset fields can appear in Advisor context. Labels can reveal people, facilities, and business units. |
| Hostnames, IPs, MACs, VLANs, interfaces, network roles and timestamps from agent, collector, and sensor | Observed facts support asset identity, scope, freshness, and location. Current asset and address history are hub projections. | Spoke memory, local inventory or sensor spool where used, and hub PostgreSQL. | In-memory sensor aggregation has a configured TTL. Acknowledged sensor batches are removed from the queue. Hub and replay-input retention **NOT DEFINED**. | Selected normalized evidence can be visible. Identifiers can reveal topology, device associations, or individuals. |
| Operating system, software, detected components, and firmware evidence from local inventory or accepted observation | Source facts and evidence feed deterministic component identity and vulnerability matching. Firmware appears when supplied by a supported evidence path. | Agent inventory files or collector output, then hub PostgreSQL after submission. | Hub and general local inventory retention **NOT DEFINED**. Installer purge and configured output locations affect local copies only. | Bounded asset, component, and vulnerability evidence may be visible. Versions and paths expose system posture. |
| Protocol and service evidence from passive capture | Ethernet/VLAN and selected protocol metadata support device observations and health. Hub derives classifications. | Frames in sensor memory. Bounded normalized evidence in memory, private spool, then PostgreSQL. | No product raw-frame archive. Replay input follows operator retention. Spool count and byte caps apply, full queues reject new batches, and accepted or duplicate acknowledgements remove queued batches. Failed or quarantined items have no general time-based expiry defined. | Normalized evidence can be visible. Raw frames and capture controls are outside Advisor tools. Protocol strings and URLs can disclose internal details. |
| Agent, collector, and sensor identity, enrollment, status, and health | Hub-bound identity and timestamps support attribution and coverage. Health is reported by the spoke and interpreted at the hub. | Protected local identity, credentials and state. PostgreSQL stores binding, hash, validation, and audit metadata. | Credentials can expire, be rotated, or be revoked. Revocation blocks future access while prior observations and audit history remain. Hub history retention **NOT DEFINED**. | Bounded normalized health and source facts may appear. Raw credentials are outside tool context. |
| Evidence, submissions, temporal history, classifications, and indexes | Hub retains source records or compatibility payloads, then derives current state, classifications, and time-window summaries. | PostgreSQL tables, JSON payloads, and relational indexes. No general-purpose AI vector store was observed on these paths. | Some parent deletions cascade in the schema. A coordinated erase, projection rebuild, and backup workflow is **NOT DEFINED**. | Advisor tools can read selected normalized evidence and derived results. Source strings and evidence may contain sensitive details. |
| Vulnerability matches, findings, risk, and decision history | Deterministic outputs from normalized evidence, reviewed catalogs, and project-owned rules. Evidence and run IDs support traceability. | PostgreSQL. | Some dependent rows cascade. A release-wide retention schedule and deletion workflow are **NOT DEFINED**. | Selected findings, risk, and vulnerability evidence can be visible. These records describe security weaknesses and prioritization. |
| Work-tracking statuses, owner and actor labels, opaque references, and available business-facing labels | Operators supply coordination context. Work-tracking identities are recorded as unverified labels. The audited schema contains site and asset labels, plus finding work metadata. | PostgreSQL work items, references, events, and asset/site data. | Removing a work reference records removal metadata. It does not erase the original label. General retention and erasure **NOT DEFINED**. | Work-tracking rows are outside the reviewed Advisor tool set. Asset or site labels can appear in normalized evidence. Labels may identify staff or sensitive systems. |
| AI questions, responses, and run metadata | Operator enters a question. The Advisor returns advisory text grounded in selected evidence. The hub logs run ID, question SHA-256, site, provider, mode, tool names, evidence count, status, and time. | Request and response processed by the hub and client, optionally by the chosen inference endpoint. PostgreSQL persists run metadata. The run table has no full question or answer column. | Hub audit retention **NOT DEFINED**. Browser, reverse proxy, application logging, operator exports, and provider persistence depend on deployment. | The inference endpoint receives the bounded request. Questions and responses may contain sensitive operational details. A plain question hash does not ensure anonymity. |
| Operator files and submitted bodies | Replay reads local capture input. Collector and agent APIs accept structured JSON. Reviewed advisory synchronization stages signed files. A general-purpose user file upload was not observed. | Replay files remain where the operator placed them. Hub can retain normalized submission or compatibility payloads. Feed staging uses its configured private location. | Feed staging is cleaned after verification. Operator files and hub submission retention are separate and generally **NOT DEFINED**. | Advisor sees supported records derived from ingestion. It has no general filesystem or upload browsing tool on this path. |
| Logs and diagnostic output | Runtime, health, service, transport, and investigation visibility. | Stdout/stderr, service logs or journal, configured local agent paths, and hub audit tables. Operator forwarding can create external copies. | OS and deployment logging settings govern service output. Product-wide log retention and central deletion **NOT DEFINED**. | Advisor uses supported status and audit summaries rather than arbitrary logs. Limit access to diagnostics because labels, paths, and addresses can occur. |
| User and account-related data, and secrets | Shared admin authentication is configured at deployment. Spoke credentials are scoped to enrolled identities. Reviewed work labels are operator assertions. A hub end-user account directory was not observed in this baseline. | Hub process configuration, protected spoke credential files, and hashed enrollment/credential records where implemented. | Revocation and rotation apply to supported credentials. Local purge is a separate action. Operator-managed secret copies and audit retention follow separate procedures. | Raw secrets are outside the intended Advisor context. Treat configuration and credential files as restricted data. |
| External advisory records and provider-related data | Reviewed catalog facts support matching and prioritization. Upstream identity, license, checksums, corrections, and activation history underpin provenance. | PostgreSQL, bounded staging, signed mirror artifacts, and the configured runtime provider when selected context is sent. | Signed catalog retention and rollback are bounded in reviewed feed workflows. Withdrawals preserve decision history. Provider storage follows its own terms. | Selected advisory and permitted lifecycle summaries may be visible. Preserve upstream attribution and treat external strings as untrusted. |

See the [schema baseline](../backend/app/migration_sql/0001_current_schema_baseline.sql),
[canonical ingestion store](../backend/app/canonical_ingestion_store.py),
[finding work schema](../backend/app/migration_sql/0005_finding_work_tracking.sql),
[Advisor API and audit write](../backend/app/main.py),
[sensor enrollment](SENSOR_ENROLLMENT.md), [agent identity](ENDPOINT_AGENT_IDENTITY.md),
and [Source Licensing Registry](SOURCE_LICENSING_REGISTRY.md).

## Operator responsibilities

- Deploy packet capture, network observation, and endpoint collection only on
  systems and networks you own or are authorized to monitor. Limit capture
  scope, spoke access, and ingress and egress to what the deployment needs.
- Restrict the hub, database, backups, local JSON and replay files, spool, and
  logs to authorized personnel. Configure transport, secret storage, log
  forwarding, and access to external providers deliberately. Keep credentials,
  sensitive labels, and unnecessary personal details out of free-form inputs.
- Set and operate retention, deletion, backup expiry, and incident procedures
  for your environment. Include copies in logs, exports, replicas, backups, and
  providers. A local uninstall or credential revocation does not delete hub
  records.
