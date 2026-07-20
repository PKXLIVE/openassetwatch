# Dependency And Security Catch-up

This record documents the July 2026 catch-up decisions made before feature
development resumes. It is intentionally scoped to dependency reproducibility,
CI coverage, the identified installer boundaries, and the overlap between the
two open draft feature/documentation pull requests.

## Dependency Decisions

The catch-up incorporates the intent of all six reviewed Dependabot pull
requests, but does not copy their patches blindly:

| PR | Decision | Catch-up treatment |
| --- | --- | --- |
| #123 | Accept | Resolve `golang.org/x/sys` at `v0.47.0`; keep the existing Go 1.25 module line and validate Windows-specific callers through the Go test suite. |
| #124 | Accept | Raise the direct Uvicorn constraint to `>=0.51.0,<1` and lock `0.51.0`, including the `standard` extra dependencies. |
| #125 | Accept | Raise the direct FastAPI constraint to `>=0.139.2,<1` and lock `0.139.2`. |
| #111 | Accept | Raise the direct SQLAlchemy constraint to `>=2.0.51,<3` and lock `2.0.51`. |
| #110 | Accept | Raise the direct Pydantic constraint to `>=2.13.4,<3` and lock `2.13.4`. |
| #102 | Accept | Update `ossf/scorecard-action` from `v2.4.0` to `v2.4.3` without changing the workflow's permissions or SARIF upload behavior. |

`backend/requirements.in` is now the direct input. The generated
`backend/requirements.txt` resolves the complete Linux/Python 3.12 runtime
graph with exact versions and SHA-256 hashes. Docker installs only that file in
hash-checking mode. Direct dependencies that previously had no bound now carry
same-major guardrails; the resolved catch-up also selects
`psycopg2-binary==2.9.12` and `pydantic-settings==2.14.2`. No direct dependency
crosses a semver major line.

Dependabot remains configured for `package-ecosystem: pip` in `/backend` and
uses the standard pip-compile input/lock pair. Its explicit `increase`
versioning strategy keeps the readable source constraint involved in future
updates.

## CI Coverage

The backend workflow now installs only the hashed lock, compiles backend source
and tests, runs the backend unit suite, runs `pip check`, audits the lock with
the maintained PyPA `pip-audit` tool, and performs a Docker Compose build/start
with the PostgreSQL and backend health checks. The existing collector, agent,
CodeQL, secret scan, license metadata, SBOM, dependency review, and Scorecard
workflows remain present. Collector CI now compiles the installer and runs the
collector unit suite on Python 3.10, 3.11, and 3.12, so Linux installer
regressions are exercised on a POSIX runner.

## Security Follow-up Assessment

### Linux sudoers temporary file: fixed in this catch-up

The legacy collector installer previously used the predictable path
`/tmp/openassetwatch-collector.sudoers` and wrote it as root before `visudo`
validation. That left a symlink/path-replacement opportunity. It now creates a
randomized temporary file inside the root-controlled `/etc/sudoers.d`
directory, flushes it, validates it with `visudo`, and atomically replaces the
destination. A regression test begins with a destination symlink and proves
that the symlink itself is replaced while its target remains unchanged.

### Windows config ACLs: closed in the production agent installer

`scripts/release/install_agent_windows_files.ps1` constructs explicit ACLs in
`Set-DirectoryAcl`: Administrators and SYSTEM retain full control,
LocalService receives read/execute on Program Files, config, and identity, and
receives modify only on state and logs. The helper applies those ACLs to each
directory and does not grant broad Everyone or Users write access.
`scripts/release/validate_agent_windows_install.py` asserts that this helper
and its ACL policy remain in the staged install contract.

### macOS service identity: closed in the production package

The staged LaunchDaemon uses `_openassetwatch` for both `UserName` and
`GroupName`. The package `postinstall` creates or strictly validates a hidden,
password-disabled account with `/var/empty` home and `/usr/bin/false` shell.
Config and identity remain root-owned and group-readable, while only state and
logs are service-owned. `validate_agent_macos_install.py` checks the plist and
manifest identity fields.

### Linux privileged installer log: fixed in this catch-up

At the branch base, root-run `log_event()` appended to
`/var/log/openassetwatch/install.log`; later `configure_linux_permissions()`
recursively transferred `/var/log/openassetwatch` to the unprivileged collector
account. On reinstall or uninstall, that account could replace `install.log`
with a symlink and cause the root installer to append to another file.

Privileged events now go to
`/var/log/openassetwatch-installer/collector-install.log`. The parent is opened
as a non-symlink directory, must be root-owned and not group/other writable,
and is mode `0700`. The log is opened relative to that held directory
descriptor with append/create and `O_NOFOLLOW`; it must be a root-owned regular
single-link file and is mode `0600`. Collector runtime logs remain under
`/var/log/openassetwatch` with the existing collector ownership. Regression
tests cover a malicious symlink, restrictive modes, append behavior, and the
separation from normal runtime logs.

## Draft PR #119 And #120 Split Recommendation

The exact file overlap is one file:

- `docs/architecture/ai-advisor.md`

The conflict is substantive. PR #119 replaces most of the 146-line overview
with a 54-line navigation hub and introduces new AI architecture assets. PR
#120 edits the original provider, MCP, and SIEM/Splunk sections in place. If
#120 lands first, #119's replacement hunk will conflict and could discard the
vendor-neutral integration direction.

PR #119 should be reduced to dashboard work:

- `README.md`
- `backend/app/static/index.html`
- `docs/CONTROL_TOWER_DEPLOYMENT.md`
- `scripts/test_control_tower_dashboard.py`
- `web/README.md`

Move these PR #119 files to a separate AI architecture follow-up based on the
eventual #120 result:

- `docs/architecture/ai-advisor-architecture.md`
- `docs/architecture/ai-advisor.md`
- `docs/architecture/ai-agent-architecture.md`
- `docs/architecture/assets/openassetwatch-ai-advisor-architecture.html`
- `docs/architecture/assets/openassetwatch-ai-advisor-architecture.svg`

PR #120 should keep the core architecture, MCP/tool model, telemetry contracts,
and event schema vendor-neutral. The planned Splunk Technology Add-on direction
should not be erased; keep it in a dedicated integration roadmap for
`TA-openassetwatch`, where OpenAssetWatch fields are mapped to Splunk
sourcetypes/CIM without making Splunk names part of the core schema.

Recommended merge order:

1. Merge this dependency/security catch-up.
2. Rebase and merge #120 after restoring the explicit dedicated Splunk
   Technology Add-on roadmap direction while retaining vendor-neutral core
   contracts.
3. Rebase #119, remove the five AI architecture files listed above, and merge
   the dashboard-only change.
4. Land the extracted #119 AI architecture work in a new follow-up based on
   #120, resolving terminology and navigation deliberately.
