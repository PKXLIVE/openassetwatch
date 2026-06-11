# Identity and Directory Enrichment Roadmap

This roadmap describes future OpenAssetWatch identity and directory enrichment.
It is documentation only. No directory integrations, API keys, credentials,
identity SDKs, account modification, Splunk Technology Add-on files, or AI logic
are implemented yet.

## Purpose

OpenAssetWatch should eventually enrich discovered assets with identity and
directory context. The goal is to connect asset visibility with device
ownership, user/device relationships, directory status, compliance status, and
account posture.

## Future Supported Sources

Future integrations may include:

- Microsoft Active Directory.
- Microsoft Entra ID.
- LDAP directories.
- Okta.
- Duo.
- Google Workspace.
- Local Windows account inventory.
- Local Linux account inventory.

## Future Metadata Fields

Future identity and directory enrichment metadata may include:

- `device_id`
- `object_id`
- `domain`
- `organizational_unit`
- `primary_user`
- `assigned_user`
- `user_owner`
- `group_memberships`
- `last_logon`
- `account_enabled`
- `stale_account_indicator`
- `mfa_status`
- `privileged_group_membership`
- `device_compliance_status`
- `join_type`
- `directory_source`
- `source_system`
- `collected_at`
- `confidence`
- `evidence`

## Future Risk Indicators

OpenAssetWatch should eventually identify:

- Asset has stale or disabled owner.
- Asset is not joined to the expected directory.
- Device is missing from AD or Entra ID.
- Device exists in directory but has not been observed recently.
- Privileged user associated with high-risk asset.
- User/device relationship is unclear.
- Device is non-compliant or unmanaged.
- Local admin account present on asset.

## Correlation Principles

OpenAssetWatch should follow these correlation principles:

- OpenAssetWatch core schema should remain vendor-neutral.
- Identity-specific fields should be stored as enrichment metadata.
- Identity records should map back to OpenAssetWatch asset IDs where possible.
- IP address alone should not be treated as stable identity.
- Every enrichment record should include source, `collected_at`, confidence, and
  evidence.

Correlation should prefer stable identifiers:

1. Directory object ID.
2. Endpoint agent ID.
3. Cloud resource ID.
4. MAC address.
5. Hostname/FQDN.
6. IP address.

## Out of Scope for Now

The following are out of scope for the current MVP:

- Do not implement Active Directory integration yet.
- Do not implement Entra ID integration yet.
- Do not implement Okta integration yet.
- Do not implement Duo integration yet.
- Do not add API keys.
- Do not add credentials.
- Do not add identity SDKs.
- Do not modify accounts automatically.
- Do not implement AI logic yet.
- Do not add Splunk TA files yet.
