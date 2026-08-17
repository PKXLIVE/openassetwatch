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

The hub-and-spoke AI showcase and future sensor contract are described in
`docs/architecture/hub-spoke-ai-showcase.md`.

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
- admin token auth is optional for local development and protects the new hub
  and AI endpoints when configured
- deterministic AI demo mode is local and makes no provider request
- external AI data sharing is disabled unless explicitly enabled and fully configured
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
AI Advisor, Policies, Reports, and Settings. It provides overview metrics, attention items,
asset mix, collector health, recent check-ins, recent evidence, discovered
assets, site cards, release metadata, and policy guardrail summaries. Empty
states explain what will appear as agents enroll and inventory evidence arrives.
A local create-site form uses `POST /api/v1/sites` to add site metadata only.
Asset search, quick filters, row details, hash routes, and Getting Started
actions run in the browser against already-loaded local API data. The browser
can copy local demo commands, but it does not execute them.

The AI Advisor view adds a focused read-only showcase without changing the
dashboard layout. It shows provider and data state, example questions, optional
site scope, evidence, affected records, recommendations, confidence, freshness,
and limitations. The optional admin-token field remains only in the page and
is not stored by browser APIs.

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
site or agent records. Destination-changing PostgreSQL query parameters such
as `hostaddr`, `host`, `port`, or `service` are rejected, and authority or
query-string credentials are redacted from diagnostic output.

If local Python reports missing modules such as `sqlalchemy` or `psycopg2`, use
the Compose seed command above or install `backend/requirements.txt` into your
local virtual environment.

Seeded records are clearly marked as demo/sample data and use documentation IP
ranges plus locally administered synthetic MAC addresses. The seed includes:

- Home, Office, and Lab demo sites with namespaced IDs (`demo-home`,
  `demo-office`, and `demo-lab`) so local reset operations cannot match ordinary
  site identifiers accidentally
- one endpoint collector and one passive network sensor per site
- recent synthetic check-ins
- twelve Windows, macOS, Linux, infrastructure, IoT, mobile, and unknown-device assets
- safe attention themes such as stale collector, missing security tooling,
  unmanaged IoT device, and unknown device samples
- cached-retry evidence at Office plus healthy, delayed, and stale sensor examples

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
| `OPENASSETWATCH_ADMIN_TOKEN` | Optional local admin token for hub/AI read endpoints. Empty disables token enforcement. |
| `OPENASSETWATCH_AI_PROVIDER` | `demo` by default; `openai-compatible` selects the generic compatible interface. |
| `OPENASSETWATCH_AI_EXTERNAL_ENABLED` | Keep `false` for an approved local model; hosted providers require `true`. |
| `OPENASSETWATCH_AI_BASE_URL` | Local or hosted API base. Local HTTP is allowlisted; hosted providers require HTTPS. |
| `OPENASSETWATCH_AI_MODEL` | Local or hosted model identifier. |
| `OPENASSETWATCH_AI_API_KEY` | Optional and omitted from requests for approved local endpoints; required for hosted providers. |
| `OPENASSETWATCH_AI_TIMEOUT_SECONDS` | Provider timeout clamped to 2-90 seconds locally and 2-30 seconds when hosted. |
| `OPENASSETWATCH_CONTROL_TOWER_VERSION` | API/server version reported by `/health`. |
| `OPENASSETWATCH_EXPECTED_AGENT_VERSION` | Placeholder expected agent version in release metadata. |
| `OPENASSETWATCH_AGENT_RELEASE_CHANNEL` | Placeholder release channel such as `local`. |
| `OPENASSETWATCH_CORS_ORIGINS` | Local UI origins allowed to call the API. |

Do not put production secrets in `.env.example` or in committed Compose files.
The exact ignored `.env` configuration for local Ollama and deterministic-mode
restoration commands are in `docs/architecture/hub-spoke-ai-showcase.md`.

## Database Model

The Control Tower schema adds these first durable records:

- `sites`: site/project records with `site_id`, name, description, and
  timestamps
- `agent_enrollments`: endpoint-agent and network-sensor enrollment records
- `sensor_enrollments`: short-lived one-time enrollment state and token digests
- `sensor_credentials`: site/sensor-bound credential digests and lifecycle state
- `sensor_identity_audit_events`: bounded, secret-free identity audit events
- `agent_checkins`: received agent health and identity metadata
- `local_inventory_collections`: raw local inventory evidence submissions
- `control_tower_assets`: normalized MVP asset records with evidence counts
- `ai_advisor_runs`: question hashes and bounded provider/tool/evidence audit metadata

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
| `POST /api/v1/observations/batches` | Accept strict, authenticated, idempotent normalized spoke batches. |
| `POST /api/v1/sensors/enroll` | Exchange a short-lived one-time passive-sensor enrollment. |
| `POST /api/v1/sensors/check-in` | Accept a site/sensor-bound passive-sensor health check-in. |
| `POST /api/v1/admin/sensor-enrollments` | Create an enrollment with configured admin authorization. |
| `GET /api/v1/admin/sensor-enrollments` | List secret-free enrollment state. |
| `GET /api/v1/admin/sensors` | List sensor identity and credential lifecycle state. |
| `GET /api/v1/control-tower/summary` | Dashboard counts for sites, agents, check-ins, assets, and evidence. |
| `GET /api/v1/control-tower/check-ins` | Recent agent check-ins. |
| `GET /api/v1/control-tower/assets` | Normalized Control Tower asset records. |
| `GET /api/v1/components` | Bounded normalized software, package, and reviewed firmware inventory. |
| `GET /api/v1/vulnerabilities` | Bounded deterministic component-to-advisory results. |
| `GET /api/v1/vulnerabilities/catalog/status` | Local advisory catalog provenance and counts; no runtime feed lookup. |
| `POST /api/v1/admin/vulnerabilities/evaluate` | Authenticated targeted or rate-limited full deterministic evaluation. |
| `POST /api/v1/admin/vulnerabilities/import` | Authenticated bounded offline catalog import. |
| `GET /api/v1/releases/agent` | Agent release metadata placeholder. |
| `GET /api/v1/hub/sites/summary` | Read-only site risk, finding, sensor, asset, and freshness summary. |
| `GET /api/v1/hub/sensors` | Read-only enrolled spoke identity and health summary. |
| `GET /api/v1/ai/status` | AI provider/mode status without secrets or configured URL. |
| `POST /api/v1/ai/advisor/query` | Read-only bounded AI Advisor query with typed evidence. |

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

- optional shared-token authentication only; no users, RBAC, or production authorization yet
- no tenant isolation enforcement yet
- no enrollment-token issuance yet
- no real release download or update execution
- no active scanning, remote commands, or credential collection
- web UI is a functional foundation, not a finished product interface
- asset normalization and deterministic findings are intentionally minimal
- no passive packet sensor, spoke queue, or retry runtime yet; only the hub contract exists
- no autonomous AI actions, vector database, or unrestricted model tools

## Network Sensor Next Step

The next sensor integration step is to implement stable local sensor identity,
outbound TLS authentication, a bounded encrypted offline queue, and idempotent
retry against `POST /api/v1/observations/batches`. Sensor collection should
remain passive-first, avoid active scans and packet upload, expose no inbound
management port by default, and preserve the hub's site, identity, evidence,
freshness, confidence, and audit boundaries.
