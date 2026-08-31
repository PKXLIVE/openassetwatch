---
name: oaw-github-workflow
description: Manage an authorized OpenAssetWatch issue-to-branch-to-PR workflow and react to CI/review feedback without merging autonomously. Use when Codex is asked to pick up repository work, create/update a PR, inspect CI failures, or continue an existing task from GitHub state.
---

# OpenAssetWatch GitHub Workflow

Use GitHub as the durable record of task state. Keep implementation work isolated and make all state changes evidence-based.

## 1. Resolve the task before writing

- Identify the exact issue/task and repository.
- Search for an existing branch or PR for the same task before creating another one.
- Read issue comments and relevant PR/review history when continuing existing work.
- Do not infer requirements solely from an issue title.
- Do not take ownership of an issue already being actively worked unless the task explicitly directs you to continue it.

If the repository has lifecycle labels such as `codex-ready`, `codex-working`, `codex-review`, `codex-blocked`, or `needs-human`, preserve their intended meaning. Do not invent or apply labels that do not exist merely to satisfy this workflow.

## 2. Branch/worktree discipline

- Start from the intended current base branch, normally `main`.
- Prefer a dedicated worktree for unattended or parallel work.
- Use a task-specific branch such as `codex/issue-123-short-purpose`.
- Never force-update `main` or a shared task branch.
- Before pushing, inspect whether the base moved and resolve conflicts normally instead of rewriting unrelated history.

## 3. PR contract

A PR prepared by autonomous execution must contain enough evidence for a human to review it without reconstructing the agent's session.

Include:

- linked task/issue and outcome;
- concise implementation summary;
- material design/security decisions;
- validation actually run and results;
- CI still pending or unavailable validation;
- migration/rollback notes when relevant;
- explicit blockers/known limitations.

Use the repository PR template and preserve its security/public-readiness checklist.

Never fabricate human DCO sign-off. Never merge to `main` autonomously.

## 4. CI repair loop

When a PR workflow fails:

1. identify the exact failed workflow/job/step;
2. inspect logs/evidence rather than guessing;
3. classify the failure as introduced, pre-existing, flaky/infrastructure, policy, or unknown;
4. if introduced by the branch, fix it and run relevant local checks before pushing;
5. if clearly transient/flaky and no code change is needed, rerun only the smallest appropriate failed job/run when authorized;
6. repeat until branch-caused failures are fixed or a real human/external blocker is reached.

Do not repeatedly rerun a deterministic failure without changing anything. Do not weaken the failing check to make the PR green.

## 5. Review feedback loop

For actionable human or automated review comments:

- verify the comment against current code;
- implement valid in-scope fixes;
- rerun affected validation;
- reply with what changed and evidence when GitHub commenting is authorized;
- leave a thread unresolved if the underlying concern is not actually resolved.

If feedback requests a material architecture/product-direction change, route it through the appropriate architecture gate instead of silently accepting it.

## 6. Ready-for-human-review state

A task is ready for human review when:

- the implementation skill's definition of done is met;
- relevant local validation has passed or unavailable checks are clearly documented;
- branch-caused CI failures are resolved as far as the environment permits;
- the PR accurately describes residual risk and pending gates;
- no autonomous merge is performed.

If a required GitHub permission, secret, protected setting, or human DCO action blocks progress, record the smallest required human action and stop at that boundary.
