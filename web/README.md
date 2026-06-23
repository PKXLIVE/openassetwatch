# Web

Reserved for the OpenAssetWatch web application.

The first Control Tower dashboard is currently served from
`backend/app/static/index.html` through the local Compose `web` service at
`http://localhost:8080`. It focuses on sites, agents/sensors, check-ins,
assets, evidence counts, and release metadata status.

The Compose `web` service depends on the backend healthcheck, so local startup
should use:

```powershell
docker compose up -d --build --remove-orphans
docker compose ps
```

Services are bound to localhost by default. If the UI reports an API error,
check backend readiness with `curl.exe http://127.0.0.1:8000/health` and view
logs with `docker compose logs -f backend`.

Future production UI work should continue toward richer asset inventory,
evidence, findings, remediation, and connector health views.
