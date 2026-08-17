# Configs

This directory contains safe OpenAssetWatch configuration examples and reserved
config namespaces.

- `advisor_tools/`: evidence review and advisor configuration patterns.
- `approved_diagnostics/`: narrowly scoped diagnostic patterns that do not
  launch scanners or mutate assets.
- `connectors/`: passive or import-only connector patterns.
- `roles/`: role and permission examples.
- `skills/`: reserved for future first-party OpenAssetWatch Skill Packs defined
  by `docs/architecture/skill-pack-contract.md`. The namespace does not yet
  imply an enabled loader/runtime, and initial Skill Packs are configuration-
  only rather than arbitrary executable scripts.
- `quarantine/`: reference-only legacy/source material. OpenAssetWatch loaders
  must refuse this path.

Production configs should use approved object identifiers such as `site_id`,
`asset_id`, `connector_id`, `sensor_id`, `approved_scope_id`, and
`evidence_artifact_id`. They must not contain raw command wrappers, raw target
URLs/IPs/CIDRs, credential material, scripts, or unrestricted scanner controls.
