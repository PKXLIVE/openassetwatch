# Scripts

Reserved for repository maintenance and local validation scripts. Runtime
installers belong under `installers/`; production tool execution wrappers
should not be added here.

- `e2e/`: local development validation helpers. These must stay defensive,
  local-only, and explicit about any backend URL they contact.
- `demo_sensor_enrollment.py`: loopback-HTTP/HTTPS synthetic proof of one-time
  sensor enrollment, bound uploads, rotation, revocation, retained evidence,
  and deterministic AI visibility. It reads administrator authorization only
  from a named environment variable and never prints issued secrets.
- `advisory_feed_sync.py`: one-shot reviewed-source administration for signed
  bundle verification, synchronization, preview, approval/rejection,
  activation, rollback, reevaluation retry, and bounded staging cleanup. It
  accepts source and server-issued IDs only; it accepts no arbitrary URL/path,
  secret, private key, unsigned mode, or skip-verification flag.
- `benchmark_advisory_feed_sync.py`: offline synthetic Ed25519, bounded-gzip,
  strict-catalog, preview-diff, and targeted-scope benchmark. It reports live
  database import/reevaluation timings as unavailable rather than simulating
  them when PostgreSQL is absent.
- `publish_osv_pypi_advisories.py`: isolated one-shot publisher for the
  licensed PyPI Advisory Database `PYSEC-*` source family transported through
  OSV.dev. It has fixed upstream paths, strict normalization, private durable
  cursor state, full/incremental/dry-run modes, Ed25519 signing, and atomic
  local outputs; it never imports or activates a catalog. Production signed
  runs require Linux-private state/output storage and fail closed on native
  Windows until private DACL validation is available.
- `demo_osv_pypi_publisher.py`: fully offline, product-authored synthetic proof
  of full and incremental publishing, signature verification, preview,
  approval, activation, deterministic match/finding/risk change, rollback, and
  read-only AI evidence. It contains no downloaded advisory data.
- `benchmark_osv_pypi_publisher.py`: bounded, offline synthetic normalization,
  deterministic catalog, signing, verification, time, payload-size, and peak
  memory benchmark for thousands of records.
- `import_advisory_catalog.py`: deprecated fail-closed entry point retained to
  explain that unsigned imports are disabled and direct operators to the
  signed-feed lifecycle.
- `demo_vulnerability_intelligence.py`: database-free fictional proof of
  normalized components, affected/fixed/uncertain firmware outcomes,
  finding/risk change after upgrade, stable history, and read-only AI evidence
  citations.
- `benchmark_vulnerability_intelligence.py`: bounded fictional offline
  normalization/catalog/indexed-matching benchmark. Defaults to 10,000 assets,
  100,000 components, and 2,000 advisories and makes no network request.
- `release/`: local release artifact helpers. These may build local binaries
  into ignored `dist/` paths, create local TAR.GZ archives from existing dist
  artifacts, create local Debian package artifacts from existing Linux dist
  artifacts, validate generated Debian package artifacts, create real RPM
  package artifacts from existing Linux dist artifacts when `rpmbuild` is
  available, validate generated RPM packages, staging trees, spec files,
  staged payloads, `/opt` layout, compatibility command paths, root-owned
  executable and libexec helper metadata,
  service-account metadata, scoped sudoers helper allowlist content, systemd
  metadata, target-install timer enablement, config/identity-guarded timer
  startup metadata, final-removal timer cleanup metadata, and Apache-2.0
  package license metadata with packaged license/notice material, without
  installing them, stage Windows Program
  Files/ProgramData install layout proofs from existing Windows dist
  artifacts without creating services, validate staged Windows
  install layout proofs without creating services, scheduled tasks, registry
  entries, or MSI packages, build unsigned Windows MSI artifacts with the
  repo-pinned WiX Toolset local tool, validate Windows MSI checksum/manifest
  metadata, provide explicit Windows signing and verification hooks, provide
  explicit Windows service install and
  uninstall helpers with dry-run validation for administrator-controlled use,
  provide explicit Windows file install and uninstall helpers with dry-run
  validation for administrator-controlled file copy and cleanup, stage and
  validate macOS LaunchDaemon install layouts from existing Darwin artifacts,
  build unsigned macOS PKG artifacts with Apple packaging tools on macOS using
  numeric receipt versions, verify Darwin slice/universal architecture inputs,
  provide explicit macOS signing and notarization hooks that sign the embedded
  binary before pkgroot staging and regenerate final checksum/manifest metadata
  after notarization/stapling, support hosted signed-release workflows that
  import signing identities into a temporary keychain and materialize
  notarization API-key material only in runner temp storage, provide a safe
  macOS uninstaller with dry-run,
  root-precondition failure, no system-Python dependency, and data-preservation
  defaults, validate
  generated release artifacts, validate release-publication manifests and
  tagged-release workflow policy, orchestrate the local release flow, stage a local
  proof-of-layout install tree under ignored `dist/` paths, create a local
  sandbox install proof under ignored `dist/` paths, remove only that local
  sandbox install proof, exercise local sandbox upgrade and rollback proofs,
  and generate metadata. Except for explicit administrator-controlled Windows
  helper execution and ignored local MSI artifact generation, these scripts
  must not install software, modify host services, modify host sudoers state,
  or execute package managers.
