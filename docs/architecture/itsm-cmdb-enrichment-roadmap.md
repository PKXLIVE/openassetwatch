# ITSM and CMDB Enrichment Roadmap

This roadmap describes future OpenAssetWatch ITSM and CMDB enrichment. It is
documentation only. No ServiceNow, Jira Service Management, ITSM SDK,
credential, ticketing, Splunk Technology Add-on, or AI logic is implemented yet.

## Purpose

OpenAssetWatch should eventually enrich discovered assets and risk findings with
ITSM and CMDB context. The goal is to connect technical asset risk to ownership,
support groups, business services, lifecycle status, and remediation workflows.

## Future Supported ITSM / CMDB Sources

Future integrations may include:

- ServiceNow.
- Jira Service Management.
- Freshservice.
- BMC Helix.
- Other CMDB or asset inventory systems.

## Future Metadata Fields

Future ITSM / CMDB enrichment metadata may include:

- `cmdb_ci_id`
- `asset_owner`
- `business_owner`
- `business_service`
- `application_service`
- `assignment_group`
- `support_group`
- `environment`
- `criticality`
- `location`
- `lifecycle_status`
- `operational_status`
- `change_window`
- `maintenance_window`
- `incident_count`
- `open_problem_records`
- `related_change_requests`
- `last_cmdb_update`
- `source_system`
- `collected_at`
- `confidence`

## Future Use Cases

OpenAssetWatch should eventually use ITSM / CMDB enrichment to:

- Identify discovered assets missing from the CMDB.
- Identify CMDB assets not recently observed by OpenAssetWatch.
- Link assets to owners and support teams.
- Prioritize risk based on business criticality.
- Route remediation recommendations to the correct group.
- Show whether a risky asset already has an incident, problem, or change record.
- Identify stale or retired CMDB records.
- Identify production assets with weak visibility.
- Identify high-risk assets without clear ownership.

## Correlation Principles

OpenAssetWatch should follow these correlation principles:

- OpenAssetWatch core schema should remain vendor-neutral.
- ITSM-specific fields should be stored as enrichment metadata.
- CMDB records should map back to OpenAssetWatch asset IDs.
- IP address alone should not be treated as stable identity.
- Every enrichment record should include source, `collected_at`, confidence, and
  evidence.

Correlation should prefer stable identifiers when available:

1. CMDB CI ID.
2. Cloud resource ID.
3. Agent ID.
4. MAC address.
5. Hostname/FQDN.
6. IP address.

## AI Advisor Role

The AI Advisor should use ITSM / CMDB enrichment to:

- Explain who owns an asset or service.
- Prioritize risks based on criticality and environment.
- Recommend the correct remediation owner or assignment group.
- Identify assets with unclear ownership.
- Explain risk in plain language for technical and non-technical users.
- Identify gaps between OpenAssetWatch discovery and CMDB records.
- Recommend ticket creation only with user approval.

AI should not:

- Automatically create incidents, changes, or tasks without user approval.
- Invent ownership or CMDB relationships.
- Modify CMDB records automatically.
- Close incidents or changes automatically.

## Splunk TA Future

The future `TA-openassetwatch` should support ITSM / CMDB-related sourcetypes
such as:

- `openassetwatch:itsm`
- `openassetwatch:cmdb`
- `openassetwatch:asset`
- `openassetwatch:finding`

The Splunk Technology Add-on should map OpenAssetWatch ITSM and CMDB fields to
CIM-compatible field names where appropriate while keeping the OpenAssetWatch
core schema vendor-neutral.

## Out of Scope for Now

The following are out of scope for the current MVP:

- Do not implement ServiceNow integration yet.
- Do not implement Jira Service Management integration yet.
- Do not add API keys.
- Do not add credentials.
- Do not add ITSM SDKs.
- Do not add Splunk TA files yet.
- Do not implement AI logic yet.
- Do not create or modify tickets automatically.
