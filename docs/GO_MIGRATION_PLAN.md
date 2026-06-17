# Go Migration Plan

OpenAssetWatch is moving its core runtime toward Go while keeping data science,
advisor, evaluation, and reporting work in Python for now. The product remains
intentionally hybrid; see `docs/PRODUCT_ARCHITECTURE.md` for the broader
runtime, deployment, licensing, and product-inspiration boundaries.

## Move Toward Go

- agent
- sensor
- collector
- local inventory
- platform detection
- network neighbor discovery
- heartbeat and check-in
- CLI
- config loading
- output writers
- installer and service helpers
- safe diagnostics

## Keep In Python For Now

- AI Advisor
- enrichment
- scoring
- reporting
- Splunk export experiments
- evaluation harness
- LLM workflows

## First-Pass Go Structure

The first pass adds:

- `cmd/oaw-agent`
- `cmd/oaw-sensor`
- `cmd/oaw-cli`
- `cmd/oaw-server`
- `cmd/oaw-mcp-stdio`
- `cmd/oaw-test-config`
- `internal/agent`
- `internal/sensor`
- `internal/collector`
- `internal/detector`
- `internal/network`
- `internal/config`
- `internal/output`
- `internal/api`
- `internal/auth`
- `internal/audit`
- `internal/storage`
- `internal/updater`
- `internal/installer`
- `pkg/schema`
- `pkg/models`
- `pkg/version`

## Migration Notes

The existing Python collector is kept as a transitional defensive MVP because
it already performs local inventory and conservative neighbor discovery. It
should not grow into a scanner launcher. New runtime work should prefer the Go
packages and commands added in this pass.

The Go foundation intentionally starts small: version output, safe config
loading, passive inventory primitives, evidence models, and installer service
specs. Larger features should be added only after the package boundaries settle.

## First Local Inventory Migration Slice

The first small migration pass moves the safest passive/local-only inventory
primitives into Go:

- `internal/collector/platform`: runtime OS, platform, architecture, and
  architecture-family detection.
- `internal/collector/host`: hostname and FQDN-if-local-hostname-already-has-one
  identity collection. It does not perform DNS lookups or external network
  calls.
- `internal/collector/network`: network interface inventory from Go standard
  library APIs, local IP/MAC observations, default gateway where safely
  available, and local neighbor-cache observations.
- `internal/collector`: local inventory assembly that emits JSON-compatible
  asset data with `collected_at`, per-observation `source` and `collected_at`
  fields, interfaces, IP/MAC addresses, optional default gateway, and neighbor
  cache entries.

The Go network migration remains passive and local-only:

- no CIDR scans
- no port scans
- no packet injection
- no credential use
- no privilege escalation
- no external network calls
- no raw command or arbitrary-argument exposure

Where OS-native commands are needed, the Go code uses fixed read-only commands
only: `Get-NetRoute`, `Get-NetNeighbor`, `route -n get default`, or `arp -a`.
Linux uses `/proc/net/route` and `/proc/net/arp` where available.

OS support differs by what each platform exposes safely without active probing:

- Windows: interface inventory uses Go standard library APIs; default gateway
  and neighbor cache use fixed PowerShell `Get-NetRoute` and `Get-NetNeighbor`
  commands when PowerShell is available. `arp -a` is a fallback for cache
  entries, but its local `Interface:` value is an address rather than a stable
  interface name, so the Go model leaves `interface` empty for that fallback.
- Linux: interface inventory uses Go standard library APIs; default gateway and
  neighbor cache prefer `/proc/net/route` and `/proc/net/arp`, avoiding command
  execution where possible.
- macOS: interface inventory uses Go standard library APIs; default gateway uses
  fixed `route -n get default`; neighbor cache uses fixed `arp -a`.

Python keeps the transitional backend integration, scheduling, policy retrieval,
software evidence detection, enrichment, reporting, advisor, and LLM workflows
for now. The Python collector should remain defensive while these pieces are
migrated incrementally.

## Windows Validation Note

On Windows, the persistent Go install may live at:

```text
C:\Program Files\Go\bin\go.exe
```

If a Codex or CI shell does not resolve `go` through PATH, use the absolute
path or update PATH for that shell. If `go test ./...` cannot create the default
Go build cache, set writable cache paths before running tests:

```powershell
$env:GOCACHE = Join-Path $env:TEMP 'oaw-system-go-cache'
$env:GOMODCACHE = Join-Path $env:TEMP 'oaw-system-go-modcache'
```
