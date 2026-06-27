# Web

Reserved for the OpenAssetWatch web application.

The Control Tower MVP dashboard is served from `backend/app/static/index.html`
through the local Compose `web` service at `http://localhost:8080`. It focuses
on overview metrics, sites, agents/sensors, recent check-ins, discovered
assets, and metadata-only release status.

The dashboard calls the local API at `http://127.0.0.1:8000` when served by the
Compose web container. It also includes a small create-site form that uses the
existing `POST /api/v1/sites` endpoint. The form creates only site metadata; it
does not enroll agents, run collection, execute updates, or perform any
credential or remote-command workflow.

The Compose `web` service depends on the backend healthcheck, so local startup
should use:

```powershell
docker compose up -d --build --remove-orphans
docker compose ps
```

Services are bound to localhost by default. If the UI reports an API error,
check backend readiness with `curl.exe http://127.0.0.1:8000/health` and view
logs with `docker compose logs -f backend`.

Validate the static dashboard wiring without starting Compose:

```powershell
python scripts/test_control_tower_dashboard.py
```

Validate it against the running local stack:

```powershell
curl.exe http://127.0.0.1:8000/health
curl.exe http://127.0.0.1:8000/api/v1/control-tower/summary
curl.exe http://127.0.0.1:8080
```

Populate local demo data for visual dashboard testing:

```powershell
python scripts/seed_control_tower_demo.py
```

The seed is local-only and idempotent for its known demo records. It creates
synthetic demo sites, endpoint agents, a passive sensor placeholder, check-ins,
and discovered assets using documentation IP ranges and locally administered
sample MAC addresses. It does not run automatically and does not perform active
collection or update execution.

Future production UI work should continue toward richer asset inventory,
evidence, findings, remediation, and connector health views.
