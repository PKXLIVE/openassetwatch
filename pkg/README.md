# Public Go Packages

Public packages hold small, reusable OpenAssetWatch primitives.

- `models`: normalized asset, evidence, finding, inventory, and heartbeat
  models.
- `schema`: safe schema constants and config field policy helpers.
- `version`: product version metadata.

These packages should remain dependency-light and safe for use by commands,
connectors, exporters, and tests.
