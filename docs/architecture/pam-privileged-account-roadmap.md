# PAM and Privileged Account Roadmap

This roadmap describes future OpenAssetWatch PAM and privileged account
enrichment. It is documentation only. No PAM integrations, API keys,
credentials, PAM SDKs, secret collection, password rotation, account
modification, Splunk Technology Add-on files, or AI logic are implemented yet.

## Purpose

OpenAssetWatch should eventually enrich asset risk with privileged account
posture. The goal is to understand whether important assets have unmanaged,
stale, unvaulted, shared, or risky privileged access tied to them.

## Future Supported PAM Sources

Future integrations may include:

- CyberArk.
- BeyondTrust.
- Delinea / Thycotic.
- HashiCorp Vault.
- Active Directory privileged groups.
- Microsoft Entra privileged roles.
- Microsoft Entra PIM.

## Important Credential Safety Rule

OpenAssetWatch must never collect, store, transmit, display, log, or export:

- Actual passwords.
- Password hashes.
- Private keys.
- API secrets.
- Session tokens.
- OAuth tokens.
- Vault credentials.
- Secret values.
- Recovery keys.

OpenAssetWatch should only collect safe metadata and posture indicators.

## Future PAM Metadata Fields

Future PAM enrichment metadata may include:

- `privileged_account_name`
- `account_type`
- `associated_asset`
- `associated_system`
- `vaulted_status`
- `password_last_rotated`
- `password_age_days`
- `rotation_policy`
- `last_login`
- `account_enabled`
- `mfa_required`
- `account_owner`
- `safe_name`
- `platform_name`
- `source_system`
- `risk_score`
- `finding_status`
- `collected_at`
- `confidence`
- `evidence`

## Future Risk Indicators

OpenAssetWatch should eventually identify:

- Privileged account not vaulted.
- Local admin account not vaulted.
- Password age exceeds policy.
- Shared privileged account.
- Stale privileged account.
- Privileged account still enabled after inactivity.
- Service account has unclear owner.
- Break-glass account missing review date.
- Privileged account tied to high-risk infrastructure asset.
- Privileged account tied to high-risk IoT or OT-like asset.
- Privileged account tied to asset with critical vulnerability.
- Privileged account tied to internet-facing asset.

## Correlation Principles

OpenAssetWatch should follow these correlation principles:

- OpenAssetWatch core schema should remain vendor-neutral.
- PAM-specific fields should be stored as enrichment metadata.
- PAM records should map back to OpenAssetWatch asset IDs where possible.
- IP address alone should not be treated as stable identity.
- Every enrichment record should include source, `collected_at`, confidence, and
  evidence.

Correlation should prefer stable identifiers:

1. PAM account ID.
2. PAM system ID.
3. Directory object ID.
4. Endpoint agent ID.
5. Cloud resource ID.
6. Hostname/FQDN.
7. IP address.

## Out of Scope for Now

The following are out of scope for the current MVP:

- Do not implement CyberArk integration yet.
- Do not implement BeyondTrust integration yet.
- Do not implement Delinea integration yet.
- Do not implement HashiCorp Vault integration yet.
- Do not add API keys.
- Do not add credentials.
- Do not collect secrets.
- Do not add PAM SDKs.
- Do not rotate passwords.
- Do not modify privileged accounts.
- Do not implement AI logic yet.
- Do not add Splunk TA files yet.
