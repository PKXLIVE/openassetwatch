# Control Tower Deployment

OpenAssetWatch Control Tower is the self-hosted API, database, and web UI
foundation that endpoint agents and future passive network sensors report into.
This first foundation is designed for local development, demos, and early
self-hosted validation.

It does not add hosted service behavior, public repository governance changes,
licensing enforcement, active scanning, credential collection, remote command
execution, or self-update.

## Local Architecture

The local Docker Compose stack runs:

- `backend`: FastAPI Control Tower API on `http://localhost:8000`
- `web`: static Control Tower dashboard on `http://localhost:8080`
- `postgres`: PostgreSQL persistence, bound to `127.0.0.1:5432`

PostgreSQL is the default persistence layer for this foundation. It is
production-friendly, works with the existing backend code, and keeps the local
demo close to the future self-hosted deployment model.

Redis is not part of the current Control Tower MVP stack because the backend,
web UI, tests, and documented runtime behavior do not use it yet. It should be
added back only with a concrete queue/cache feature and matching healthcheck.

## Safe Defaults

- database, API, and web ports bind to localhost by default
- `.env.example` contains placeholders only
- collector token auth is optional for local development and empty by default
- no production secrets are committed
- the release endpoint is metadata-only and never downloads or executes updates
- ingestion endpoints reject unsafe top-level command and credential fields

## Startup Readiness

Docker Compose includes healthchecks for:

- `postgres`: `pg_isready`
- `backend`: HTTP GET `/health`
- `web`: HTTP GET `/`

Where supported by Docker Compose, dependency ordering waits for:

- backend after Postgres is healthy
- web after backend is healthy

The backend image installs Python dependencies at build time through
`backend/Dockerfile`. The `./backend` source directory remains bind-mounted for
local development reloads, so code changes still apply without rebuilding the
image unless dependencies change.

## Local Startup

Copy the example environment file if you want to customize local values:

```powershell
Copy-Item .env.example .env
```

Start the stack:

```powershell
docker compose up -d --build --remove-orphans
```

Wait for healthy services:

```powershell
docker compose ps
```

Open the UI:

```text
http://localhost:8080
```

The dashboard is a static Control Tower MVP UI with a left navigation shell and
client-side views for Dashboard, Assets, Collectors, Sites, Evidence, Findings,
Policies, Reports, and Settings. The Dashboard view is the overview command
center: it summarizes the environment in one sentence, shows eight KPI cards,
visualizes asset mix, operating systems/platforms, collector health, and site
health, then previews top findings, unknown/unmanaged assets, recent check-ins,
recent evidence, assets needing review, recently discovered assets, stale
collectors/sensors, and site cards. Empty states explain what will appear as
agents enroll and inventory evidence arrives. A local create-site form uses
`POST /api/v1/sites` to add site metadata only. Asset search, quick filters, row
details, hash routes, and Getting Started actions run in the browser against
already-loaded local API data. The browser can copy local demo commands, but it
does not execute them.

Check API health:

```powershell
curl.exe http://localhost:8000/health
```

Expected shape:

```json
{
  "status": "healthy",
  "service": "openassetwatch-control-tower",
  "version": "0.1.0"
}
```

Stop the stack:

```powershell
docker compose down
```

View logs:

```powershell
docker compose logs -f backend
```

Validate the static dashboard wiring without starting Compose:

```powershell
python scripts/test_control_tower_dashboard.py
```

The dashboard test checks the expected local endpoints, navigation sections,
empty/error states, safe policy copy, asset filters, and create-site form. It
also verifies the static page does not load external assets.

Validate the running dashboard and backing API:

```powershell
curl.exe http://127.0.0.1:8000/health
curl.exe http://127.0.0.1:8000/api/v1/control-tower/summary
curl.exe http://127.0.0.1:8000/api/v1/sites
curl.exe http://127.0.0.1:8000/api/v1/agents
curl.exe http://127.0.0.1:8080
```

## Optional Local Demo Seed Data

A fresh local stack starts empty. To populate the dashboard with deterministic
synthetic sample data for visual testing, run the local-only demo seed after
Compose is healthy. The recommended path uses the backend Compose image so the
required Python dependencies are already available:

```powershell
docker compose --profile demo run --rm demo-seed
```

If you already have the backend Python dependencies installed locally, the host
Python path remains available:

```powershell
python scripts/seed_control_tower_demo.py
```

The script defaults to the local Compose PostgreSQL endpoint at
`127.0.0.1:5432` and refuses non-local database hosts. Inside Docker Compose,
the service host `postgres` is allowed only by the explicit demo profile command
or by setting `OPENASSETWATCH_DEMO_SEED_ALLOW_COMPOSE_HOST=1` with the seed
script. Arbitrary external database hosts remain refused. The seed is
idempotent for the known demo records: running it again refreshes the same demo
sites, agents, check-ins, inventory collections, and assets without duplicating
site or agent records.

If local Python reports missing modules such as `sqlalchemy` or `psycopg2`, use
the Compose seed command above or install `backend/requirements.txt` into your
local virtual environment.

Seeded records are clearly marked as demo/sample data and use documentation IP
ranges plus locally administered synthetic MAC addresses. The seed includes:

- `home-lab` and `small-office` demo sites
- two endpoint agents and one passive network sensor placeholder
- recent synthetic check-ins
- Windows workstation, macOS laptop, Linux server, printer, network switch,
  smart TV/IoT, unmanaged mobile, and unknown-device assets
- safe attention themes such as stale collector, missing security tooling,
  unmanaged IoT device, and unknown device samples

The seed does not run automatically, does not add active scanning, does not
create credentials, and does not execute remote commands or update behavior.

Reset local development data:

```powershell
docker compose down -v --remove-orphans
```

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `OAW_POSTGRES_PASSWORD` | Local PostgreSQL password placeholder for Compose. |
| `OPENASSETWATCH_COLLECTOR_TOKEN` | Optional local collector token. Empty disables token enforcement. |
| `OPENASSETWATCH_CONTROL_TOWER_VERSION` | API/server version reported by `/health`. |
| `OPENASSETWATCH_EXPECTED_AGENT_VERSION` | Placeholder expected agent version in release metadata. |
| `OPENASSETWATCH_AGENT_RELEASE_CHANNEL` | Placeholder release channel such as `local`. |
| `OPENASSETWATCH_CORS_ORIGINS` | Local UI origins allowed to call the API. |

Do not put production secrets in `.env.example` or in committed Compose files.

## Database Model

The Control Tower schema adds these first durable records:

- `sites`: site/project records with `site_id`, name, description, and
  timestamps
- `agent_enrollments`: endpoint-agent and network-sensor enrollment records
- `agent_checkins`: received agent health and identity metadata
- `local_inventory_collections`: raw local inventory evidence submissions
- `control_tower_assets`: normalized MVP asset records with evidence counts

The existing collector tables remain in place for the earlier Python collector
and policy work.

## API Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | API health and version. |
| `GET /api/v1/sites` | List site/project records. |
| `POST /api/v1/sites` | Create or update a site/project record. |
| `GET /api/v1/agents` | List enrolled endpoint agents and future sensors. |
| `POST /api/v1/agents/enrollments` | Create or update an agent/sensor enrollment record. |
| `POST /api/v1/agents/check-in` | Accept agent check-in metadata and update last seen state. |
| `POST /api/v1/collections/local-inventory` | Accept Go agent local inventory JSON and normalize basic assets. |
| `GET /api/v1/control-tower/summary` | Dashboard counts for sites, agents, check-ins, assets, and evidence. |
| `GET /api/v1/control-tower/check-ins` | Recent agent check-ins. |
| `GET /api/v1/control-tower/assets` | Normalized Control Tower asset records. |
| `GET /api/v1/releases/agent` | Agent release metadata placeholder. |

## Agent Configuration Direction

Agents will point at the Control Tower with a local config containing the
self-hosted server URL and site ID:

```json
{
  "server_url": "http://localhost:8000",
  "site_id": "site-local"
}
```

The agent identity file provides the non-secret `site_id` and `agent_id`.
Enrollment tokens are future work and must be treated as secrets when added.

## Limitations

- no authentication/authorization for admin UI/API yet
- no tenant isolation enforcement yet
- no enrollment-token issuance yet
- no real release download or update execution
- no active scanning, remote commands, or credential collection
- web UI is a functional foundation, not a finished product interface
- asset normalization is intentionally minimal

## Network Sensor Next Step

The next sensor integration step is to reuse the same enrollment model with
`agent_type: network-sensor`, then define a passive sensor evidence envelope.
Sensor ingestion should remain passive-first, avoid active scans by default,
and preserve the same site, agent/sensor, evidence, and audit boundaries used
by endpoint agents.
