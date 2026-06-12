# Collector Policy and Bundles

## Purpose

OpenAssetWatch collectors should eventually receive safe backend-assigned
configuration from the OpenAssetWatch backend. The model is similar in concept
to a Splunk Deployment Server assigning deployment apps to Universal
Forwarders, but tailored for OpenAssetWatch collector safety, identity, and
local-network visibility.

Conceptual flow:

```text
OpenAssetWatch Backend -> deployment policy -> collector config bundle -> OpenAssetWatch Collector
```

This document describes the future architecture only. Policy download and
remote bundle application are not implemented yet.

## Assignment Model

Collectors should check in with identity, deployment, platform, and version
metadata that the backend can use for safe policy assignment.

Collector check-in metadata may include:

- `collector_guid`
- `collector_id`
- `deployment_id`
- `labels`
- `platform`
- `collector_version`
- currently applied policy version, if any

The backend can assign policies based on:

- `collector_guid`
- `deployment_id`
- `labels`
- platform
- collector version
- install profile

`collector_guid` should remain the strongest match for a specific installed
collector. Deployment metadata and labels should support grouping by business
unit, site, location, environment, rollout ring, or install campaign.

## Policy Bundle Contents

A future collector config bundle may include:

- scheduler settings
- collector mode: `device`, `network`, or `hybrid`
- enabled enrichment modules
- safe module configuration
- log level
- module intervals
- one-time safe actions, such as run inventory now

Example future modules:

- `open_detector`
- `reverse_dns`
- `mdns`
- `ssdp`
- `netbios`
- `snmp`
- `nmap_light`, later and disabled by default
- passive sensor, later and disabled by default

Bundles should describe desired collector behavior using explicit schema fields.
They should not contain arbitrary scripts or shell command strings.

## Safety Boundaries

Policy bundles must stay inside clear safety boundaries:

- no arbitrary shell commands from the backend
- only schema-defined actions and modules
- active scanning disabled by default
- packet capture disabled by default
- sensitive values must not be logged
- a local emergency disable or hold file must override backend policy

The collector should treat backend policy as configuration, not as remote code
execution. Any module that can increase network activity, require privileges,
or touch sensitive local data should require explicit schema support and clear
local safety defaults.

## Policy Lifecycle

A future policy lifecycle should include:

- assigned
- downloaded
- validated
- applied
- failed
- rollback or fallback to last known good config
- status reported back to the backend

The collector should report policy status fields such as:

- `applied_policy_id`
- `applied_policy_version`
- `policy_hash`
- `last_policy_check`
- `policy_status`
- `policy_error`, if any

If a policy cannot be validated or applied, the collector should keep running
with the last known good local configuration where possible and report the
failure clearly.

## Bundle Integrity

Future bundles should support:

- policy version
- SHA256 hash
- optional signature later
- schema validation
- minimum collector version
- platform constraints

The collector should validate bundle schema, platform compatibility, and minimum
version requirements before applying any backend-assigned policy.

## Config Precedence

Future collector configuration should be layered in this order:

1. built-in defaults
2. installer config
3. local override config
4. backend-assigned policy
5. emergency local disable or hold file

The emergency local override must be able to prevent remote policy application.
This gives an operator a local recovery path if a backend policy is incorrect,
unsafe for a specific network, or incompatible with a collector host.

## Suggested Future Endpoints

Future policy endpoints may include:

- `POST /api/v1/collectors/checkin`
- `GET /api/v1/collectors/policy`
- `GET /api/v1/collectors/policies/{policy_id}`
- `POST /api/v1/collectors/policy-status`

These endpoints are future scope only. The current collector should continue to
use local configuration, check-in, and inventory upload behavior until policy
download is intentionally implemented.

## Out of Scope

Do not implement the following as part of this architecture note:

- policy download
- backend UI
- arbitrary remote command execution
- package or binary updates
- Nmap enablement
- packet capture
- Zeek
- Suricata
- masscan
