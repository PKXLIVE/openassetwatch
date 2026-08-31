# Codex Autonomous Execution for OpenAssetWatch

This document describes the repository-side controls for letting Codex continue bounded engineering work with less routine supervision while preserving OpenAssetWatch architecture, validation, security, and human merge gates.

## What this adds

The autonomous-development layer is intentionally separate from product runtime architecture.

- `AGENTS.md` — repository-wide engineering/autonomy rules and definition of done.
- `.codex/config.toml` — project-scoped approval/Auto-review defaults.
- `.codex/hooks.json` — lifecycle hook configuration.
- `.codex/hooks/stop_guard.py` / `stop_guard.ps1` — one-pass completion review before a turn ends.
- `.agents/skills/oaw-task-execution/` — issue/task implementation workflow.
- `.agents/skills/oaw-validation/` — evidence-based validation workflow.
- `.agents/skills/oaw-github-workflow/` — issue/branch/PR/CI/review workflow.
- Existing specialized skills continue to apply, including architecture review when triggered.

These files do not authorize an agentic Skills runtime inside the OpenAssetWatch product and do not change product authority boundaries.

## Safety model

Codex may continue routine, non-destructive engineering work inside the assigned repository/worktree without asking for every implementation choice. It should keep iterating through failures that it can safely diagnose and repair.

Human/external gates remain for:

- production or destructive actions;
- credentials/secrets not already available through an approved mechanism;
- material architecture/product-invariant changes;
- consequential privacy/licensing/legal/safety decisions without policy;
- new paid services/material external cost;
- human DCO/legal identity attestations;
- final merge to `main`.

The repository's existing CI/security gates remain authoritative. Autonomous execution must not weaken a check to obtain a green result.

## One-time local setup

1. Open the OpenAssetWatch repository as the Codex project.
2. Confirm Codex recognizes the project `.codex/config.toml` and root `AGENTS.md`.
3. Open `/hooks` in Codex and review the project-local Stop hook.
4. Trust the hook only after confirming it points to the checked-in `.codex/hooks/stop_guard.*` scripts.
5. Run one small documentation-only test task before relying on unattended code changes.

Project-local hooks are intentionally subject to Codex's hook trust mechanism. If their definition changes later, review/trust the new hash again before unattended use.

## Recommended task shape

Give Codex a bounded outcome, constraints, and verification criteria. Avoid broad instructions such as "keep improving the project."

Example:

```text
/goal

Complete OpenAssetWatch GitHub issue #<number>.

Outcome:
Implement the complete issue and leave the branch ready for human PR review.

Constraints:
- Follow AGENTS.md and all applicable skills.
- Preserve approved OpenAssetWatch architecture and product invariants.
- Work only in a dedicated branch/worktree.
- Do not merge to main.
- Do not fabricate DCO sign-off or other human attestations.
- Do not perform production/destructive actions.

Verification:
- Add/update tests for changed behavior.
- Run the applicable validation in docs/LOCAL_DEV_SETUP.md.
- Diagnose and fix branch-caused failures, then rerun validation.
- Review the final diff for secrets, debug artifacts, unrelated edits, and missing docs.
- Prepare/update a PR with validation evidence.

Continue until the definition of done is satisfied or a stop condition in AGENTS.md genuinely requires human/external input.
```

## Queue model for scheduled execution

For repeatable unattended work, use GitHub issues as the durable queue. Recommended labels are:

- `codex-ready` — explicitly approved for autonomous pickup;
- `codex-working` — currently being executed;
- `codex-review` — implementation is awaiting human review/merge;
- `codex-blocked` — cannot continue without an external prerequisite;
- `needs-human` — a specific human decision/action is required.

Create these labels in GitHub before relying on the queue. Do not let Codex infer work from every open issue.

A scheduled-task instruction can use this pattern:

```text
Continue bounded OpenAssetWatch development from GitHub.

First, look for an existing OpenAssetWatch task/PR already in progress by this automation and continue it safely if one exists.

Otherwise, select only the highest-priority open issue explicitly labeled `codex-ready` that is not already assigned to active work.

For the selected issue:
- read AGENTS.md and applicable skills;
- inspect the issue, relevant docs/code/tests, and existing related PRs;
- create/use an isolated task branch/worktree;
- implement the smallest complete solution;
- run applicable validation;
- diagnose and repair branch-caused failures instead of stopping at the first failed test;
- inspect the final diff;
- create/update a PR with observed validation evidence;
- do not merge to main;
- do not fabricate DCO sign-off.

If a genuine stop condition is reached, record the exact blocker and smallest human action needed. If no `codex-ready` issue exists, do not invent work.
```

## Local versus cloud scheduling

Use local scheduled execution when the task needs the checked-out repository, local Docker/Compose, locally installed toolchains, or local hardware. The machine and Codex app must remain available for local project work.

Cloud execution is useful when the work can be done entirely from cloud-accessible repository/context and does not require a folder or hardware that exists only on the local machine. Keep local-hardware validation explicitly pending when a cloud run cannot prove it.

## Completion hook behavior

The Stop hook does not blindly keep Codex running forever.

On the first attempted stop it requests exactly one final pass against `AGENTS.md` definition-of-done criteria. Codex should finish any remaining safe in-scope work or confirm the evidence it actually observed.

When the Stop event is invoked again with `stop_hook_active=true`, the hook allows the turn to end. This prevents a continuation loop.

The hook is a final quality gate, not a substitute for tests or CI.

## CI and review repair loop

When a task PR has a failed GitHub Action:

1. read the exact workflow/job/step failure and logs;
2. classify it as branch-caused, pre-existing, transient/infrastructure, policy, or unknown;
3. fix branch-caused failures and rerun the relevant local validation before pushing;
4. rerun a failed CI job without code changes only when evidence indicates the failure was transient/flaky;
5. do not weaken the check to obtain a pass;
6. keep the PR unmerged until the normal human gate is satisfied.

Review feedback follows the same evidence loop: verify the comment, make valid in-scope changes, rerun affected validation, and document the result.

## Definition of a successful autonomous run

A successful run is not "Codex produced code." It is:

- the assigned outcome is implemented within scope;
- relevant behavior is tested;
- applicable local validation was observed passing or unavailable checks are explicitly identified;
- introduced failures are repaired;
- the final diff is clean and reviewed;
- relevant documentation is current;
- the PR explains evidence and residual risk;
- irreversible/production/legal/architecture/merge gates remain with the appropriate human or policy boundary.
