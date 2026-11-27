# OpenAssetWatch Overview

The Next.js Overview reads site, asset, collector, and finding data from the
existing Control Tower API. Run it alongside the standard local stack.

## Run locally

Start the backend from the repository root according to the
[Control Tower deployment guide](../docs/CONTROL_TOWER_DEPLOYMENT.md#local-startup).
Run the frontend with Node.js 24 or later and Corepack. The package manifest
pins pnpm and its integrity hash.

```powershell
cd frontend
corepack pnpm install --frozen-lockfile --ignore-scripts
corepack pnpm dev
```

Open `http://127.0.0.1:3000`. The Next.js server defaults to the local API at
`http://127.0.0.1:8000`. To use a different API origin, set `OAW_API_ORIGIN`
in the server environment before starting Next.js. The origin accepts HTTP on
loopback and HTTPS for other hosts. Next.js listens on loopback in the supplied
scripts and forwards a fixed set of read-only GET requests. Findings that
require an authorized session appear as unavailable. Run this build as an
opt-in local workspace alongside the standard static Control Tower.

The shared header remains available across the dashboard views. Use Ctrl + K
or the search launcher to find loaded inventory and open findings in the
selected scope. The header includes a labeled demonstration inbox and a local
Account menu. The site selector provides display context for the full inventory
response. Server-side tenant and site authorization is required before a shared
deployment. The shell forwards neither browser credentials nor cookies.

The header theme toggle saves your choice in this browser. The dashboard follows
your system color scheme until you choose a theme. The sidebar and favicon share
the official PNG in `public/brand/`.

## Reusable panel families

`app/panel-families.tsx` contains the first six reusable, read-only panel
families from the accepted dashboard design: metric summary, time series,
ranked bar, composition, table, and status matrix. Their typed helpers in
`lib/panel-families.ts` preserve measured zero versus missing data, retain gaps
in time series, cap ranked and matrix output, group omitted composition values
as `Other`, and disclose truncated tables. A zero denominator is labeled
"Share unavailable" while preserving raw counts. Stale and partial states
remain visible; status cells use explicit labels, including `unknown` for
missing checks, so color never carries the meaning by itself.

These components are a rendering library for the Overview application; they do
not activate the draft Skill Pack or create a dashboard planner, catalog
approval, query engine, or authorization boundary. The existing Overview keeps
its current API data sources and behavior. Timeline/event rail,
relationship view, and evidence/provenance panel remain outside this milestone.

## Integration decision

This application continues the existing Next.js work because its typed API
adapter, scoped links, chart components, and tests provide a basis for the
shared shell. The standard Compose and FastAPI entry points remain available.
[PR #187](https://github.com/PKXLIVE/openassetwatch/pull/187) provides a useful
reference for evaluating the Jinja2 shell and login flow. Shared deployments
need a server-side session and scoped read APIs before the shell can serve
protected data or display a verified profile.

## Read the charts

- Exposure trend counts currently active and acknowledged findings by first-seen
  interval. The page indicates partial data when a status is capped at 200 rows.
- Discovered assets groups the current inventory by the API device classification.
  The donut segments, legend, and bars all open the same filtered inventory.
- Reporting collectors have a check-in within the previous 15 minutes. The
  collector detail view distinguishes stale and missing check-ins.
- Recent activity shows the latest inventory observation per asset. This view
  and the newly observed KPI share the selected date range with the trend.

Drilldown URLs retain site, date range, and the exact end time used to calculate
the selected interval. The underlying records reflect the API's current state.

## Validate

```powershell
corepack pnpm test
corepack pnpm build
corepack pnpm typecheck
```

Use `corepack pnpm start` to serve the build. For populated charts, the deployment guide
documents the optional synthetic seed for the local Compose database. Use
`python scripts/test_control_tower_dashboard.py` from the repository root to
check the existing static dashboard.

The single-document pnpm lockfile records the resolved packages and integrity
hashes for Dependency Review. A version-scoped override removes Next.js
16.4.6's unused optional Sharp dependency and its libvips packages from the
resolved graph. The logo uses the unoptimized image path. Other optional
packages, including platform-specific Next.js SWC binaries, remain resolved.
Apply the [third-party software policy](../docs/THIRD_PARTY_SOFTWARE_POLICY.md)
to the exact artifacts before distribution or hosted deployment.
