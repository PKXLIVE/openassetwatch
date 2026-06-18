# Local E2E Validation

This guide validates the current manual OpenAssetWatch agent workflow against a
local backend. By default, the helper validates:

1. collect passive local inventory to a temporary JSON file
2. submit that JSON to the local backend ingestion endpoint
3. confirm the backend returns an accepted HTTP response

With `-IncludeCheckIn`, the helper validates the fuller manual flow:

1. create a temporary non-secret identity file
2. send an agent check-in with that identity file
3. collect passive local inventory with that identity file
4. submit that JSON to the local backend ingestion endpoint
5. confirm check-in and submit return accepted HTTP responses

This is a local development helper only. It does not add daemon mode,
scheduling, licensing enforcement, UI behavior, active network collection,
credential handling, or external service calls.

## Prerequisites

- Go is installed and available as `go`, or you know the path to `go.exe`.
- Backend Python dependencies are installed in `.venv/`.
- The backend is running locally.
- The backend URL is explicit, such as `http://localhost:8000`.

The helper intentionally allows only local backend hosts such as `localhost`,
`127.0.0.1`, or `::1`.

## Start Backend

From the repository root:

```powershell
$env:PYTHONPATH = "backend"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In another terminal, confirm the backend is healthy:

```powershell
Invoke-WebRequest http://localhost:8000/health -UseBasicParsing
```

## Run The Helper

From the repository root:

```powershell
.\scripts\e2e\local_collect_submit.ps1 -ServerUrl http://localhost:8000 -SiteId site-local
```

If Go is not on PATH, the helper also checks the standard Windows install path:
`C:\Program Files\Go\bin\go.exe`.

The helper writes inventory to a temporary file and deletes it after a
successful run. Use `-KeepTemp` if you need to inspect the generated JSON:

```powershell
.\scripts\e2e\local_collect_submit.ps1 -ServerUrl http://localhost:8000 -SiteId site-local -KeepTemp
```

To run the full current manual agent flow:

```powershell
.\scripts\e2e\local_collect_submit.ps1 -ServerUrl http://localhost:8000 -SiteId site-local -IncludeCheckIn
```

With `-IncludeCheckIn`, the helper creates a temporary `identity.json`, runs
`oaw-agent identity init`, sends `oaw-agent check-in`, collects inventory with
`--identity-file`, submits the inventory JSON, and deletes the temp files unless
`-KeepTemp` is used.

The helper intentionally uses a temporary explicit identity file instead of the
default agent identity path. This keeps local E2E validation from creating or
modifying privileged paths such as `%ProgramData%\OpenAssetWatch\agent` or
`/etc/openassetwatch/agent`.

The helper also requires an explicit `-ServerUrl` instead of relying on the
default agent config file. This keeps the live E2E path local and obvious.
Agent config file behavior can be validated manually with the commands below.

## Manual Equivalent

```powershell
go run ./cmd/oaw-agent collect --once --site-id site-local --output inventory.json

go run ./cmd/oaw-agent submit --file inventory.json --server-url http://localhost:8000
```

With a local non-secret agent identity file:

```powershell
go run ./cmd/oaw-agent identity init --site-id site-local --output identity.json

go run ./cmd/oaw-agent check-in --identity-file identity.json --server-url http://localhost:8000

go run ./cmd/oaw-agent collect --once --identity-file identity.json --output inventory.json

go run ./cmd/oaw-agent submit --file inventory.json --server-url http://localhost:8000
```

With a local non-secret agent config file:

```powershell
go run ./cmd/oaw-agent config init `
  --server-url http://localhost:8000 `
  --site-id site-local `
  --output config.json

go run ./cmd/oaw-agent identity init --site-id site-local --output identity.json

go run ./cmd/oaw-agent check-in --identity-file identity.json --config config.json

go run ./cmd/oaw-agent collect --once --config config.json --output inventory.json

go run ./cmd/oaw-agent submit --file inventory.json --config config.json
```

Explicit flags remain highest priority. For example, `--server-url` overrides
config `server_url`, and `--site-id` overrides config `site_id`.

Expected success output includes an HTTP 2xx status:

```text
submitted local inventory collection: HTTP 200
```

## Safety Model

The helper:

- requires an explicit local `ServerUrl`
- refuses URL credentials, query strings, and fragments
- uses temporary identity and collection files
- does not print request bodies or response bodies
- does not collect credentials
- does not add enrollment tokens
- does not call external services
- does not perform CIDR discovery, port checks, or packet injection
- fails clearly if the backend is not reachable

## Troubleshooting

- `Backend is not reachable`: start the backend and confirm `/health` works.
- `ServerUrl must point to a local backend`: use `http://localhost:8000` or
  `http://127.0.0.1:8000`.
- `Go is not available`: install Go, restart the shell if needed, and verify
  `go version` works.
- `Local collection failed`: verify `go run ./cmd/oaw-agent collect --once
  --site-id site-local` works.
- `Submit failed`: confirm the backend has
  `POST /api/v1/collections/local-inventory` available and that the server URL
  points to the local backend.
