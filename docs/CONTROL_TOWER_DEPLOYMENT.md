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
- `redis`: reserved local service dependency, bound to `127.0.0.1:6379`

PostgreSQL is the default persistence layer for this foundation. It is
production-friendly, works with the existing backend code, and keeps the local
demo close to the future self-hosted deployment model.

## Safe Defaults

- database, Redis, API, and web ports bind to localhost by default
- `.env.example` contains placeholders only
- collector token auth is optional for local development and empty by default
- no production secrets are committed
- the release endpoint is metadata-only and never downloads or executes updates
- ingestion endpoints reject unsafe top-level command and credential fields

## Local Startup

Copy the example environment file if you want to customize local values:

```powershell
Copy-Item .env.example .env
```

Start the stack:

```powershell
docker compose up -d
```

Open the UI:

```text
http://localhost:8080
```

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
