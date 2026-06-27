# Collector Policy and Bundles

## Purpose

OpenAssetWatch collectors should eventually receive safe backend-assigned
configuration from the OpenAssetWatch Control Plane. The model is similar in
concept to a Splunk Deployment Server assigning deployment apps to Universal
Forwarders, but tailored for OpenAssetWatch collector safety, identity, and
local-network visibility.

The formal architecture name is **OpenAssetWatch Control Plane**. **Control
Tower** is the product-facing name for the local dashboard and operations
surface. Architecture docs should use control plane when describing backend
services and Control Tower when describing the product UI or operator surface.

The OpenAssetWatch Control Plane is the backend system that collectors report
to for:

- check-in
- inventory upload
- policy retrieval
- deployment labels
- capability assignment
- license/entitlement validation
- revocation
- status reporting

Internal service names may include:

- Collector Deployment Service
- Policy Service
- License / Entitlement Service
- Collector API

Conceptual flow:

```text
OpenAssetWatch Control Plane -> deployment policy -> collector config bundle -> OpenAssetWatch Collector
```

This document describes the future architecture only. Policy download and
remote bundle application are not implemented beyond the safe MVP policy
retrieval endpoint.

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
- `collector_id`
- `deployment_id`
- `labels`
- platform
- collector version
- install profile

Collectors should also report:

- `supported_capabilities`: what the collector can safely do on the current
  host.
- `enabled_capabilities`: what the collector is currently doing.

Policy may include `assigned_capabilities`, which are the capabilities the
OpenAssetWatch Control Plane allows or requests. Assigned capabilities should
not be blindly enabled when they are not supported by the collector host.
Future license/entitlement validation should use these fields for assignment,
revocation, and reporting.

For the future tenancy, ownership, licensing, entitlement, and revocation model,
see `docs/architecture/control-plane-tenancy-licensing.md`.

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

Scanner-launcher style capabilities such as Nmap or masscan are not valid
production collector capabilities. Passive sensor behavior belongs in the
separate OpenAssetWatch sensor path and must remain explicitly scoped and
disabled until that path is implemented.

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

The MVP status endpoint accepts `applied`, `failed`, `held`, or `ignored`.

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

## MVP Policy Assignment Storage

The MVP backend can store collector policies and simple policy assignments.
This lets the OpenAssetWatch Control Plane return an assigned policy instead of
only returning the built-in default policy.

MVP tables:

- `collector_policies`
- `policy_assignments`

Policy lookup supports these assignment fields:

- exact `collector_guid`
- exact `collector_id`
- exact `deployment_id`
- exact platform
- simple JSON label selector matching

When more than one assignment matches, the highest `priority` value wins.
Disabled assignments and disabled policies are ignored. If no assignment
matches, the backend falls back to the built-in `default-local-collector`
policy.

This MVP does not enforce tenant ownership, licensing, or entitlement rules yet.
Those checks should be added before this model is used in a managed or SaaS
deployment.

## Suggested Endpoints

Policy-related endpoints may include:

- `POST /api/v1/collectors/checkin`
- `GET /api/v1/collectors/policy`
- `GET /api/v1/collectors/policies/{policy_id}`
- `POST /api/v1/collectors/policy-status`

The MVP implements policy retrieval, policy status reporting, and simple
database-backed policy assignment. Rich assignment logic, tenant enforcement,
license enforcement, and backend UI workflows are future scope.

Development-only admin endpoints currently include:

- `GET /api/v1/admin/policies`
- `POST /api/v1/admin/policies`
- `GET /api/v1/admin/policy-assignments`
- `POST /api/v1/admin/policy-assignments`

These endpoints are for local Control Plane development and must gain proper
authentication, authorization, and audit behavior before production use.

## Out of Scope

Do not implement the following as part of this architecture note:

- backend UI
- tenant enforcement
- license enforcement
- arbitrary remote command execution
- package or binary updates
- Nmap enablement
- packet capture
- Zeek
- Suricata
- masscan
