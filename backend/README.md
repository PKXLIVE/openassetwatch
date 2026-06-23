# OpenAssetWatch Backend

The backend is the first OpenAssetWatch Control Tower API. It is a FastAPI
service backed by PostgreSQL through SQLAlchemy.

## What It Provides

- health and version endpoint
- site/project records
- endpoint-agent and future network-sensor enrollment records
- agent check-in ingestion
- Go agent local inventory ingestion
- raw inventory evidence persistence
- basic Control Tower asset normalization
- release/artifact metadata placeholder
- static dashboard mount at `/ui`
- legacy Python collector ingestion and policy endpoints

## Local Run

From the repository root:

```powershell
docker compose up -d
```

Then check:

```powershell
curl.exe http://localhost:8000/health
```

Open the dashboard:

```text
http://localhost:8080
```

## Database

The default local deployment uses PostgreSQL. Runtime schema initialization is
implemented in `backend/app/database.py`; first-run Compose initialization uses
`database/schema.sql`.

Control Tower tables include:

- `sites`
- `agent_enrollments`
- `agent_checkins`
- `local_inventory_collections`
- `control_tower_assets`

## Tests

Use the project virtual environment when available:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s backend\tests -t backend
```

The unit tests mock the database boundary for endpoint behavior and test local
normalization/schema helpers without requiring a live PostgreSQL instance.

## Safety Boundaries

The backend does not perform active scanning, credential collection, remote
command execution, package installation, self-update, or release download
execution. Ingestion treats client-submitted data as passive observations, not
privileged truth.
