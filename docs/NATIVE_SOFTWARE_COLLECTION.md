# Native Software And Package Collection

OpenAssetWatch's authenticated Go endpoint agent collects bounded,
machine-level installed-software evidence and submits it through the existing
`POST /api/v1/agents/inventory` contract. It does not add another ingestion
route or another component authority. The canonical flow is:

```text
reviewed native source -> bounded Go collector -> bound endpoint credential
-> canonical inventory collection -> normalized component and source presence
-> deterministic vulnerability, finding, and risk evaluation
-> Control Tower and read-only AI evidence
```

Authentication proves which enrolled agent sent a snapshot. It does not prove
that every reported package fact is correct. Deterministic findings and risk,
not the endpoint or AI Advisor, remain authoritative.

## Supported sources and limits

| Platform | Source ID | Method | Canonical ecosystem | First-version scope |
| --- | --- | --- | --- | --- |
| Windows | `windows-uninstall-64` | native read-only HKLM 64-bit uninstall registry view | `generic` | machine only; registry view is not package architecture |
| Windows | `windows-uninstall-32` | native read-only HKLM WOW64/32-bit uninstall registry view | `generic` | machine only; registry view is not package architecture |
| Linux | `linux-dpkg` | fixed `/usr/bin/dpkg-query` or `/bin/dpkg-query` with fixed arguments | `deb` | installed system packages |
| Linux | `linux-rpm` | fixed `/usr/bin/rpm` or `/bin/rpm` with fixed arguments | `rpm` | installed system packages |
| macOS | `macos-pkgutil` | fixed `/usr/sbin/pkgutil` receipt list and receipt information | `generic` | machine receipt database |

Collection is capped at 2,000 normalized components, 5,000 source lines, eight
MiB of stdout, four KiB of discarded diagnostic output, and a 20-second
overall deadline. Package names, versions, vendors, source record IDs, safe
metadata, and diagnostics have smaller field limits. Ordering and duplicate
suppression are deterministic.

Linux and macOS execute no shell. Executable paths and arguments are compiled
into the agent. A candidate executable must be a root-owned, single-linked,
non-writable regular file at the reviewed absolute path. Locale is fixed to
`C`. Output and errors are classified into bounded codes; raw stdout, stderr,
registry values, or plist documents are never sent to the hub.

Windows uses native registry APIs and never invokes PowerShell, WMI
`Win32_Product`, MSI product queries, or user-hive enumeration. It retains
only display name, display version, publisher, registry product/subkey ID,
machine scope, and source view. The view is not asserted as package
architecture. It does not retain uninstall
commands, license keys, serial numbers, or install paths.

macOS v1 intentionally stops at `pkgutil` receipts. It does not traverse home
directories, application bundles, Spotlight data, plug-ins, or package
scripts. Application-bundle coverage, Alpine, Arch, Snap, Flatpak, and
container-image inventories are future adapters, not current capabilities.

## Source result contract

Each reviewed source reports one result with a source ID, platform,
observation time, bounded record count, status, truncation flag, safe error
code, and up to eight bounded limitations:

- `complete`: the reviewed machine source finished without truncation or an
  error. Limitations such as machine-only scope still remain visible.
- `partial`: usable records exist, but malformed records, timeout/output
  bounds, or another declared limitation prevented a complete source view.
- `unsupported`: the fixed native source is unavailable on the host.
- `failed`: the reviewed source could not be queried safely.

Components include ecosystem, name, version, architecture, package manager,
install scope, collection source, source record ID, evidence method,
observation time, confidence, and a small allowlisted metadata map. The client
cannot submit site authority, trust, finding state, vulnerability state,
severity, risk, management state, or server-issued evidence IDs.

The backend accepts native source results only on a bound endpoint-agent
inventory. It verifies the exact platform/source/ecosystem/manager/method
mapping, record counts, unique source records, timestamps, system scope, and
diagnostic status before creating a server-derived `css_*` source-snapshot ID.
The canonical collection, agent source, site, asset, and source ID form the
snapshot identity.

## Complete-source withdrawal

Migration `0004_native_software_source_presence.sql` adds append-only source
snapshots, latest source status, and per-component source-presence projection.
A complete source may mark an omitted presence inactive only when all of these
persisted values match:

- site and canonical asset;
- bound endpoint-agent source identity;
- reviewed package source and platform/view scope;
- a newer server-validated canonical source snapshot.

Partial, failed, unsupported, truncated, timed-out, malformed, stale,
rejected, and lower-trust compatibility input never withdraw prior presence.
One Windows view cannot withdraw the other; dpkg cannot withdraw RPM; one
agent cannot withdraw another; and no source crosses site or asset scope.

Projection locks the persisted site before component or presence rows. The
source snapshot, presence activation, complete-snapshot omission update,
canonical component state, and history record share one transaction. A
component remains current while any source-presence row remains active. The
final valid withdrawal marks the component no longer observed but deletes no
component, snapshot, presence, evidence, match, finding, or evaluation
history. Identical inventory replay returns its original canonical
acknowledgement and runs no evaluation; conflicting replay fails closed.

Downstream classification, vulnerability, finding, and risk evaluation starts
only after a new canonical collection commits. A projection or evaluation
failure is recorded as bounded retryable state without changing ingestion
acceptance. Targeted vulnerability reconciliation includes prior advisory IDs,
so a final component withdrawal resolves current matches and findings and
removes their current risk contribution while preserving history.

## API, dashboard, and AI evidence

The existing component API returns current and historical components plus up
to eight bounded source-provenance records. Existing agent detail output adds
the latest bounded status for each native source: attempt time, last complete
time, count, truncation, safe error/limitations, and canonical collection ID.

The Control Tower adds small text-safe source and current/historical labels; it
does not render raw metadata or install paths. The AI Advisor's read-only
component tool can explain current versus historical state, exact native
source status, deterministic vulnerability linkage, findings, and risk. Its
answer reconciles only persisted server-issued agent, collection, source
snapshot, component, match, finding, and risk evidence IDs. It cannot run
package commands, change state, or interpret a partial source as absence.

## Packaged credential directory

The agent credential record stays separate from inventory data:

| Package | Credential directory | Installed policy |
| --- | --- | --- |
| Windows MSI | `%ProgramData%\OpenAssetWatch\Agent\state\credential` | service SID read/write/execute; SYSTEM and Administrators full control; no broad Users/Everyone/Authenticated Users write grant |
| Linux DEB/RPM | `/var/lib/openassetwatch/agent/credential` | `openassetwatch:openassetwatch`, mode `0700`; credential file is mode `0600`, single-linked, and service-owned |
| macOS PKG | `/Library/Application Support/OpenAssetWatch/Agent/state/credential` | `_openassetwatch:_openassetwatch`, mode `0700`; symlink/non-directory replacement is rejected |

Package lifecycle jobs create a fictional credential file, verify service
access and restrictive ownership/permissions, verify repair/upgrade/downgrade
preservation where supported, and verify uninstall preservation. Windows CI
performs installed-MSI DACL checks; source validation alone is not treated as
installed ACL proof. macOS checks run only on macOS, and Linux ownership/link
checks run inside installed DEB/RPM lifecycle environments. Production Windows
signing and macOS signing/notarization remain separate release gates.

## Demonstration, benchmark, and validation

The demonstration uses only fictional packages and a product-authored
fictional advisory. It creates and drops a random disposable PostgreSQL
database and requires an explicit environment gate:

```powershell
$RepoRoot = (Get-Location).Path
docker compose run --rm --no-deps `
  --volume "${RepoRoot}:/source-repo:ro" `
  --env OPENASSETWATCH_NATIVE_SOFTWARE_DEMO=1 backend `
  sh -ceu 'install -d -m 0755 /tmp/oaw-demo
cp -R /source-repo/backend /tmp/oaw-demo/backend
cp -R /source-repo/database /tmp/oaw-demo/database
cp -R /source-repo/scripts /tmp/oaw-demo/scripts
chmod -R go-w /tmp/oaw-demo
cd /tmp/oaw-demo
python scripts/demo_native_software_collection.py'
```

When mounting a local checkout, use a read-only source mount and copy the
backend, database manifest, and scripts into a Linux-owned temporary directory
before migration validation. The script proves bound enrollment, complete
source ingestion, identical replay, partial preservation, later complete
withdrawal, match/finding/risk transition, and server-ID-cited AI evidence.

The benchmark defaults to 2,000 unique components plus 200 duplicate synthetic
source records. It measures synthetic record generation/deduplication,
contract parsing, serialized payload size, authenticated canonical ingestion,
component/vulnerability/finding/risk evaluation, and Python peak memory:

```powershell
$RepoRoot = (Get-Location).Path
docker compose run --rm --no-deps `
  --volume "${RepoRoot}:/source-repo:ro" `
  --env OPENASSETWATCH_NATIVE_SOFTWARE_BENCHMARK=1 backend `
  sh -ceu 'install -d -m 0755 /tmp/oaw-benchmark
cp -R /source-repo/backend /tmp/oaw-benchmark/backend
cp -R /source-repo/database /tmp/oaw-benchmark/database
cp -R /source-repo/scripts /tmp/oaw-benchmark/scripts
chmod -R go-w /tmp/oaw-benchmark
cd /tmp/oaw-benchmark
python scripts/benchmark_native_software_collection.py --components 2000'
```

These are local development measurements, not production capacity claims.
Native Windows count-only smoke and installed-package ACL evidence come from
their platform-specific tests/CI; Linux container tests cannot validate a
Windows registry or macOS receipt database.

Focused checks include:

```powershell
go test ./internal/collector/software ./internal/collector ./pkg/models ./cmd/oaw-agent

docker compose run --rm --no-deps backend `
  python -m unittest tests.test_native_software_collection `
    tests.test_ai_advisor tests.test_vulnerability_matching
```

PostgreSQL lifecycle tests are explicitly gated and create only randomized
databases with a fixed test prefix. See `docs/DATABASE_MIGRATIONS.md` for the
Linux-owned-copy command pattern and migration governance.

No real host package list, registry export, command output, credential, signed
runtime artifact, or downloaded advisory corpus belongs in Git.
