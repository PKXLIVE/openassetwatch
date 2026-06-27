# Security Policy

OpenAssetWatch is security-adjacent software, so we take vulnerabilities seriously.

## Supported versions

| Version | Support |
| --- | --- |
| `main` | Active development. Security fixes land here first. |
| Latest tagged release | Receives critical fixes when practical. |
| Older releases | Best-effort only. Please upgrade. |

## Reporting a vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Use GitHub private vulnerability reporting:

https://github.com/PKXLIVE/openassetwatch/security/advisories/new

Include:

- A clear description of the issue
- Steps to reproduce
- Affected commit, version, package, or artifact
- Impact and suggested severity
- Whether you want public credit

## Scope

In scope:

- Source code in this repository
- Official OpenAssetWatch release artifacts
- Official OpenAssetWatch packaging scripts
- Default local development configuration

Out of scope:

- Third-party services
- User-modified deployments
- Attacks requiring physical access
- Social engineering
- Denial-of-service testing against public infrastructure
- Testing systems you do not own or have permission to test

## Disclosure process

We aim to acknowledge valid reports within 72 hours and provide an initial triage update within 14 days.

## Safe harbor

Good-faith security research that follows this policy, avoids privacy violations, avoids service disruption, and does not access or modify data beyond what is necessary to prove the issue will not be treated as hostile activity by the project maintainers.
