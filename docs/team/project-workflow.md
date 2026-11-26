# Project Workflow

This is the change flow for every OpenAssetWatch contribution, human or
agent-assisted. [CONTRIBUTING.md](../../CONTRIBUTING.md) and
[GOVERNANCE.md](../../GOVERNANCE.md) hold the policy; this page shows the
order.

1. **Scope.** Start from an issue or maintainer assignment. Check for an
   existing branch or pull request first.
2. **Branch.** Work on a focused branch from current `main`, never on `main`
   itself.
3. **Design.** For architecture, data source, external API or AI changes, use
   the [architecture review skill](../../.agents/skills/oaw-architecture-review/SKILL.md).
   Follow the [accepted decisions](../architecture/decisions/README.md).
4. **Build and test.** Add or update tests with each behavior change. Run the
   checks in [DEVELOPMENT_VALIDATION.md](../DEVELOPMENT_VALIDATION.md).
5. **Sign off.** Every human-authored commit, including AI-assisted commits,
   carries a DCO `Signed-off-by` trailer from the person responsible for it.
   Commits by recognized automation authors remain exempt, as the DCO check
   defines.
6. **Open a pull request.** It states the outcome, scope, validation actually
   run, limitations and pending CI. Required CI checks must pass.
7. **Review.** At least one independent review covers the whole change.
   - Security-sensitive, legal, release, installer and governance changes need
     maintainer approval.
   - Changes to paths listed in [CODEOWNERS](../../.github/CODEOWNERS) request
     the code owner's review.
8. **Merge.** Maintainers merge. Nothing merges itself.

Documentation distinguishes implemented, planned and experimental
capabilities. CTEM documents use the labels in
[docs/ctem/README.md](../ctem/README.md).
