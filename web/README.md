# Web

Reserved for the OpenAssetWatch web application.

The Control Tower MVP dashboard is served from `backend/app/static/index.html`
through the local Compose `web` service at `http://localhost:8080`. It focuses
on a compact app shell with Dashboard, Assets, Collectors, Sites, Evidence,
Findings, Policies, Reports, and Settings views. The Dashboard view is a
full-canvas command-center overview with a top search/scope strip, an
environment summary sentence, eight KPI cards, larger local SVG charts for asset
mix and operating-system/platform coverage, collector health, site health, top
findings, unknown/unmanaged assets, recent check-ins, recent evidence, assets
needing review, recently discovered assets, stale collectors/sensors, and site
cards. Getting Started guidance, demo seed copy, and metadata-only release
status live under Settings so the overview stays focused on visibility, health,
findings, and activity.

The dashboard calls the local API at `http://127.0.0.1:8000` when served by the
Compose web container. It also includes a small create-site form that uses the
existing `POST /api/v1/sites` endpoint. The form creates only site metadata; it
does not enroll agents, run collection, execute updates, or perform any
credential or remote-command workflow.

The Assets view includes browser-side Catalog and Detailed Inventory modes.
Catalog mode is the default and groups assets by device type/category, site,
platform/OS, evidence source/data source, and attention state. Cards show counts,
badges, descriptions, and a View Assets action. Selecting a card switches to
Detailed Inventory, applies a client-side filter, updates the breadcrumb, and
shows Back to Catalog. Detailed Inventory preserves the searchable/filterable
table and read-only detail panel for the data already returned by the local
Control Tower API. Top search, chart, catalog, and review-queue drilldowns
update local UI state only. The Policies and Reports views are informational
only; they do not execute checks, commands, downloads, or remediation.

Sidebar navigation uses local hash routes such as `#dashboard`, `#assets`, and
`#settings`. Refresh reloads local API data, the attention banner opens the
read-only Findings view, Getting Started buttons navigate to safe local helper
panels, and rows update read-only asset or collector detail panels.

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

The smoke test verifies the expected sections, local API endpoints, full-canvas
Dashboard and Assets views, safe empty/error states, top search controls,
grouped Catalog/Inventory asset modes, create-site form wiring, asset filters,
and lack of external static assets.

Validate it against the running local stack:

```powershell
curl.exe http://127.0.0.1:8000/health
curl.exe http://127.0.0.1:8000/api/v1/control-tower/summary
curl.exe http://127.0.0.1:8080
```

Populate local demo data for visual dashboard testing:

```powershell
docker compose --profile demo run --rm demo-seed
```

That Compose command uses the backend image dependencies and connects only to
the local Compose database service. If backend Python dependencies are already
installed locally, `python scripts/seed_control_tower_demo.py` also works
against `127.0.0.1:5432`.

The seed is local-only and idempotent for its known demo records. It creates
synthetic demo sites, endpoint agents, a passive sensor placeholder, check-ins,
and discovered assets using documentation IP ranges and locally administered
sample MAC addresses. The data includes safe attention themes such as stale
collector, missing security tooling, unmanaged IoT, unmanaged mobile, and
unknown device samples. It does not run automatically and does not perform
active collection or update execution.

Future production UI work should continue toward richer asset inventory,
evidence, findings, remediation, and connector health views.
