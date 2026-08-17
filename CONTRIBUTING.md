# Contributing to OpenAssetWatch

Thank you for helping improve OpenAssetWatch.

## Contribution license

OpenAssetWatch is licensed under the Apache License, Version 2.0.

By submitting a pull request, issue, suggestion, patch, documentation change, configuration, detection, or other contribution for inclusion in this repository, you agree that the contribution is provided under Apache-2.0 unless you explicitly state otherwise in writing and the maintainers accept the alternate terms.

## Developer Certificate of Origin

OpenAssetWatch uses the Developer Certificate of Origin, Version 1.1. The complete, unmodified certificate is in the repository root at `DCO`.

Every human-authored commit submitted after adoption of this policy must include a `Signed-off-by` trailer. The sign-off certifies that you created the contribution or otherwise have the right to submit it under the license indicated by the repository.

Create a signed-off commit with:

```bash
git commit --signoff -m "type: describe the change"
```

The commit message will include a trailer similar to:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Use a real name or established contributor identity and an email address associated with the commit. The sign-off is a legal attestation by the contributor; maintainers must not add another person's sign-off without that person's authorization.

The DCO sign-off is different from a cryptographic commit signature. Contributors may use both.

### Fixing a missing sign-off

For the most recent commit:

```bash
git commit --amend --signoff --no-edit
git push --force-with-lease
```

For multiple commits on a branch:

```bash
git rebase --signoff origin/main
git push --force-with-lease
```

Review the rewritten history before pushing. Coordinate with collaborators before rewriting a shared branch.

### Web-based commits

When the repository's web-commit sign-off setting is enabled, commits created through the GitHub web interface are signed off automatically by the commit author. Command-line commits still require `--signoff`.

### AI-assisted and third-party material

Using an AI assistant does not transfer responsibility for a contribution. The contributor remains responsible for confirming that the submitted material is accurate, appropriately licensed, free of secrets, and eligible for submission under the DCO.

Do not copy code, documentation, diagrams, rules, prompts, datasets, or configuration from another project unless the license permits the intended use and all required attribution and notice obligations are satisfied. When in doubt, describe the underlying idea in original OpenAssetWatch terms or ask a maintainer before submitting the material.

## Development workflow

1. Fork the repository.
2. Create a focused feature branch.
3. Keep changes reviewable and within the stated scope.
4. Add or update tests where practical.
5. Sign off every commit.
6. Open a pull request against `main`.

## Required checks

Pull requests should pass the relevant CI checks before merge, including the DCO check when applicable.

The initial DCO rollout may temporarily grandfather pull requests that were opened before this policy existed. New commits added after adoption should be signed off.

## Security-sensitive changes

Changes touching collectors, installers, release workflows, authentication, permissions, network behavior, package signing, AI tools, model routing, or publication workflows may require extra maintainer review.

## No secrets

Do not commit credentials, API keys, tokens, private keys, certificates, customer data, or private infrastructure details.

## Code of conduct

All contributors are expected to follow `CODE_OF_CONDUCT.md`.
