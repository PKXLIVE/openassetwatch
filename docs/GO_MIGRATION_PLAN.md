# Go Migration Plan

OpenAssetWatch is moving its core runtime toward Go while keeping data science,
advisor, and reporting work in Python for now.

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

## Keep In Python For Now

- AI Advisor
- enrichment
- scoring
- reporting
- Splunk export experiments
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
