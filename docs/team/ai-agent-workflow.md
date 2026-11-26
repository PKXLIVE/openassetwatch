# AI Development Agent Workflow

AI development agents follow the shared instructions in
[AGENTS.md](../../AGENTS.md) at the repository root. [CLAUDE.md](../../CLAUDE.md)
imports the same file, so every agent reads one standard. This page summarizes
how the pieces fit; `AGENTS.md` is the authority.

## How work is assigned

1. **The maintainer assigns each task.** The assignment names the agent, task,
   workspace, branch, baseline commit and mode.
2. **The agent validates the workspace** with the maintainer's private
   workspace validator before starting, and stops on any mismatch.
3. **The agent works only inside the assignment's mode and explicit grants**,
   as defined in `AGENTS.md`.
4. **A different reviewer checks the branch read-only** before the pull
   request is marked ready.
5. **The maintainer reviews and merges.**

## Boundaries

- **Development tooling only.** Agent instruction files and configuration are
  never product-runtime AI instructions. See the runtime boundary in
  [AGENTS.md](../../AGENTS.md).
- **Private configuration stays out of Git.** That covers workstation
  settings, validators, assignment registries and personal preferences.
- **One writer per branch.** Each agent preserves work it did not create.
- **The pull request is the durable handoff.** Another agent can continue from
  it without the original session.

See [project-workflow.md](project-workflow.md) for the review and merge flow
that applies to every contributor.
