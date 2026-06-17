# Control Plane Tenancy and Licensing

## Purpose

The OpenAssetWatch Control Plane is the backend system that coordinates
collector identity, ownership, policy, capability assignment, licensing, and
status reporting.

The Control Plane should eventually manage:

- collector enrollment
- collector identity
- tenant/customer ownership
- policy assignment
- capability assignment
- license/entitlement validation
- collector revocation
- status reporting

This document is architecture planning only. It does not implement backend
enforcement, SaaS billing, or a license server.

## Tenant/Customer Isolation

Future managed and SaaS deployments should define ownership and isolation
concepts such as:

- `tenant_id`
- `organization_id` or `customer_id`
- `deployment_id`
- `collector_guid`
- `collector_id`
- `labels`

In SaaS or managed mode, tenant/customer ownership must come from server-side
authentication and enrollment context. It must not be accepted blindly from
values sent by a collector.

Collector-provided values such as `collector_id`, `deployment_id`, and `labels`
can help with grouping, search, and operations, but they should not be treated
as authoritative ownership boundaries.

## Collector Identity

`collector_guid` is the stable installed collector identity. It is generated
once on the collector host, preserved across reinstall, and removed only during
purge uninstall.

`collector_id` is a friendly/admin-readable identifier. It can be useful in
commands, logs, and operations, but it is not as strong as `collector_guid` for
matching a specific installed collector.

`deployment_id` represents rollout, site, business unit, environment, lab, or
campaign grouping.

`labels` are flexible grouping metadata for use cases such as owner, install
profile, device group, ring, or support team.

The backend should assign collector ownership during enrollment. The collector
can report identity and grouping metadata, but server-side enrollment and auth
context should decide which tenant/customer owns the collector.

## Capability Model

Capability state should be represented with separate fields:

- `supported_capabilities`: what the collector can technically do on the
  current host.
- `enabled_capabilities`: what the collector is currently doing.
- `assigned_capabilities`: what the OpenAssetWatch Control Plane allows or
  requests.
- `denied_capabilities`: what the OpenAssetWatch Control Plane blocks.

Current and future capability names include:

- `device_inventory`
- `network_neighbors`
- `open_detector`
- `reverse_dns`
- `mdns`
- `ssdp`
- `netbios`
- `snmp`
- `vulnerability_enrichment`
- `cmdb_enrichment`
- `identity_enrichment`
- `ai_advisor`
- `splunk_export`

Collectors should ignore assigned capabilities they do not support. The Control
Plane can use supported, enabled, assigned, and denied capability fields to
explain why a feature is unavailable, disabled, blocked, or pending future
implementation.

## License / Entitlement Model

Future license and entitlement records may include:

- `license_id`
- `tenant_id` or `customer_id`
- `license_tier`
- `allowed_capabilities`
- `max_collectors`
- `max_assets`
- `expiration`
- `status`: `active`, `expired`, `suspended`, or `revoked`
- `offline_grace_period`
- `license_source`: `cloud_check`, `signed_license_file`, or `dev_mode`

Authentication proves who the collector is. Licensing controls what the
tenant/customer is allowed to use.

The MVP should keep development behavior simple, but future managed deployments
should evaluate entitlements before assigning capabilities or returning policy
bundles.

## Policy Assignment Flow

Future policy assignment should follow this high-level flow:

```text
collector check-in
-> backend validates collector identity
-> backend resolves tenant/customer
-> backend evaluates license/entitlements
-> backend compares supported/enabled/assigned capabilities
-> backend returns safe policy bundle
```

The policy response should be schema-defined and should never include arbitrary
remote commands. The Control Plane should return only capabilities and modules
that are allowed by entitlement and safe for the collector's platform and
version.

## Revocation Model

Future revocation types may include:

- token revocation
- collector disablement
- license revocation
- capability revocation
- emergency local hold file
- backend denylist by `collector_guid`

Token revocation prevents authenticated collector API access. Collector
disablement blocks a collector from receiving active policy. License revocation
or suspension blocks tenant/customer capability use. Capability revocation
removes one or more features from assigned policy.

An emergency local hold file must remain a local operator override. It should
prevent remote policy or update application even if the backend would otherwise
assign new policy.

## Future Data Model

Future backend tables may include:

- `tenants`
- `licenses`
- `collector_tokens`
- `collector_policies`
- `collector_capabilities`
- `capability_entitlements`
- `policy_assignments`
- `collector_revocations`

The MVP already includes simple `collector_policies` and
`policy_assignments` tables so the Control Plane can return assigned collector
policies instead of only returning a hardcoded default. That MVP storage is not
tenant-enforced yet. In managed or SaaS mode, policy assignment must be scoped
by server-side tenant/customer context and license entitlement checks.

The exact schema should be designed when enrollment, auth, licensing, and policy
assignment move beyond the MVP. The core collector payload should remain
vendor-neutral and should not embed SaaS billing assumptions.

## Safety Principles

The tenancy, licensing, and policy model should follow these safety principles:

- no arbitrary remote commands
- no secrets/passwords collected
- active scanning disabled by default
- packet capture disabled by default
- SNMP disabled unless explicitly assigned
- collector ignores unsupported capabilities
- emergency hold file overrides remote policy

Licensing and entitlement logic should restrict feature access without turning
the collector into a remote execution agent.

## Out of Scope

The following are out of scope for this documentation PR:

- SaaS billing
- payment processing
- backend UI
- full enrollment implementation
- license server implementation
- signed license files
- policy assignment code
- package update system
