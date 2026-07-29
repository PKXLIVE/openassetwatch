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
- idempotent outbound observation batches with site/sensor provenance
- one-time passive-sensor enrollment and bound, rotatable credentials
- site and sensor health/freshness summaries
- deterministic and optional external AI Advisor providers
- bounded read-only AI evidence tools and audit metadata
- focused AI Advisor dashboard view
- release/artifact metadata placeholder
- static dashboard mount at `/ui`
- legacy Python collector ingestion and policy endpoints

## Local Run

From the repository root:

```powershell
docker compose up -d --build --remove-orphans
```

Wait for healthy services:

```powershell
docker compose ps
```

Then check backend health:

```powershell
curl.exe http://localhost:8000/health
```

Open the dashboard:

```text
http://localhost:8080
```

View backend logs:

```powershell
docker compose logs -f backend
```

Stop the stack:

```powershell
docker compose down
```

Reset local development data:

```powershell
docker compose down -v --remove-orphans
```

The backend image installs Python dependencies at build time through
`backend/Dockerfile`; the source tree remains bind-mounted into `/app` for
local development reloads. The image uses pip hash-checking mode against the
fully resolved `backend/requirements.txt` lock.

## Dependency Inputs And Lock

`backend/requirements.in` is the readable direct-dependency manifest and the
file maintainers should edit. `backend/requirements.txt` is generated with
Python 3.12 on Linux by `pip-tools==7.5.3`; it pins the complete runtime graph
and includes package hashes. Dependabot's `/backend` pip configuration uses the
standard pip-compile input/lock pair and increases the source constraint when
an accepted release requires it.

From the repository root, regenerate the lock in the same Python environment
as the backend image:

```powershell
$CompileCommand = "python -m piptools compile --upgrade --generate-hashes --strip-extras --newline=lf --output-file backend/requirements.txt backend/requirements.in"
docker run --rm --volume "${PWD}:/workspace" --workdir /workspace `
  --env "CUSTOM_COMPILE_COMMAND=$CompileCommand" python:3.12-slim `
  sh -c 'python -m pip install --disable-pip-version-check --no-cache-dir pip-tools==7.5.3 && python -m piptools compile --upgrade --generate-hashes --strip-extras --newline=lf --output-file backend/requirements.txt backend/requirements.in'
```

Review both files together. The lock targets Linux, so verify it in the same
container environment rather than installing it into a Windows virtual
environment:

```powershell
docker build --tag openassetwatch-backend-lock-check backend
docker run --rm openassetwatch-backend-lock-check python -m pip check
docker run --rm --entrypoint sh openassetwatch-backend-lock-check `
  -c 'python -m pip install --disable-pip-version-check --no-cache-dir pip-audit==2.10.1 && python -m pip_audit --require-hashes --disable-pip -r /tmp/openassetwatch-requirements.txt'
```

## Database

The default local deployment uses PostgreSQL. Runtime schema initialization is
implemented in `backend/app/database.py`; first-run Compose initialization uses
`database/schema.sql`.

Control Tower tables include:

- `sites`
- `agent_enrollments`
- `sensor_enrollments`
- `sensor_credentials`
- `sensor_identity_audit_events`
- `agent_checkins`
- `local_inventory_collections`
- `control_tower_assets`
- `ai_advisor_runs`

## Tests

Run backend tests through the Linux/Python 3.12 backend image so the hashed
lock, platform-specific dependencies, and test runtime match Docker:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace/backend backend `
  python -m unittest discover -s tests -v
```

The unit tests mock the database boundary for endpoint behavior and test local
normalization/schema helpers without requiring a live PostgreSQL instance.
Static showcase and seed tests use only the standard library:

```powershell
python scripts/test_control_tower_dashboard.py
python scripts/test_control_tower_demo_seed.py
```

See `docs/architecture/hub-spoke-ai-showcase.md` for provider configuration,
the observation batch contract, trust boundaries, local Ollama activation, and
deterministic-mode restoration steps.
See `docs/SENSOR_ENROLLMENT.md` for the one-time sensor enrollment API,
credential storage, rotation/revocation, and development shared-token boundary.

## Safety Boundaries

The backend does not perform active scanning, credential collection, remote
command execution, package installation, self-update, or release download
execution. Ingestion treats client-submitted data as passive observations, not
privileged truth.
