# Security Tool Policy

OpenAssetWatch is a defensive asset intelligence platform. Its production
tools must help users discover assets, understand what they are doing, identify
risk, and decide what to do next.

## Allowed Production Patterns

Production tools should be passive-first, evidence-based, scoped, and safe by
default. Preferred patterns include:

- evidence review
- passive inventory
- external exposure connectors
- approved diagnostics
- cloud and IaC posture review
- artifact and static analysis
- internal result viewing
- finding and remediation workflows

Production tool configs should identify approved objects, not raw execution
targets. Safe fields include:

- `site_id`
- `asset_id`
- `domain_id`
- `sensor_id`
- `connector_id`
- `approved_scope_id`
- `evidence_artifact_id`
- `review_profile`

## Prohibited Production Patterns

OpenAssetWatch production tools must not become a penetration testing platform,
C2 framework, exploitation framework, payload generator, credential attack
platform, webshell, terminal platform, or raw scanner launcher.

Do not preserve or expose production tools that include:

- arbitrary command or shell execution
- arbitrary Python or script execution
- raw command or argument wrappers
- `additional_args` passthrough
- raw target URLs, IPs, CIDRs, or file paths
- raw usernames, passwords, hashes, API keys, tokens, or secret values
- exploit modules or payload generation
- brute force, credential validation, pass-the-hash, lateral movement, or
  privilege escalation
- C2, webshell, terminal access, active fuzzing, or unrestricted scanners

## Quarantine Rule

Unsafe old/source project material must be moved to `configs/quarantine/` or
documented under `docs/legacy-source-review/`. Quarantined files are not active
OpenAssetWatch tools and must not be loaded by production code.

## Current Enforcement

This first pass removed scanner-oriented capability names from active default
collector policy and added a collector-side policy validation guard for unsafe
module names. Safe production config examples now live under `configs/`.

The Go config loader and transitional Python collector config loader now refuse
paths under `configs/quarantine/` so reference material cannot be accidentally
loaded through active OAW config paths.
