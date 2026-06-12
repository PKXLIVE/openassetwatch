# Local Development

Start the local stack:

```sh
docker compose up -d
```

Check backend health:

```sh
curl http://localhost:8000/health
```

## Environment

The Docker Compose backend service uses this database setting by default:

```sh
DATABASE_URL=postgresql+psycopg2://openassetwatch:openassetwatch_change_me@postgres:5432/openassetwatch
```

Collector API key auth is optional in local development. If this variable is
unset or empty, collector check-in and inventory upload stay open:

```sh
OPENASSETWATCH_COLLECTOR_TOKEN=change-me-dev-token
```

When set, collector POST requests must include:

```text
X-OpenAssetWatch-Collector-Token: change-me-dev-token
```

Inventory persistence stores raw collector submissions in Postgres and performs
minimal MVP normalization into collector, asset, IP observation, and software
detection records.

Collector normalization prefers `collector_guid` when present and falls back to
`collector_id` for older collectors.

Send a collector heartbeat/check-in:

```sh
curl -X POST http://localhost:8000/api/v1/collectors/checkin \
  -H "Content-Type: application/json" \
  -H "X-OpenAssetWatch-Collector-Token: change-me-dev-token" \
  -d '{
    "collector_id": "local-dev-collector-01",
    "collector_guid": "11111111-1111-4111-8111-111111111111",
    "collector_name": "Local Dev Collector",
    "hostname": "PK-RDNA2",
    "collector_version": "0.1.0",
    "mode": "hybrid",
    "platform": {
      "system": "windows",
      "architecture": "amd64"
    },
    "deployment": {
      "deployment_id": "home-lab-cincinnati",
      "business_unit": "lab",
      "site": "home",
      "environment": "test",
      "install_ring": "pilot"
    },
    "labels": {
      "owner": "dion",
      "device_group": "windows-test",
      "install_profile": "local-collector"
    },
    "status": "healthy",
    "message": "manual smoke test"
  }'
```

Send a collector inventory payload:

```sh
curl -X POST http://localhost:8000/api/v1/collectors/inventory \
  -H "Content-Type: application/json" \
  -H "X-OpenAssetWatch-Collector-Token: change-me-dev-token" \
  -d '{
    "schema_version": "0.1",
    "collector": {
      "id": "local-dev-collector-01",
      "name": "Local Dev Collector"
    },
    "collector_guid": "11111111-1111-4111-8111-111111111111",
    "collector_version": "0.1.0",
    "mode": "hybrid",
    "platform": {
      "system": "windows",
      "architecture": "amd64"
    },
    "deployment": {
      "deployment_id": "home-lab-cincinnati"
    },
    "labels": {
      "owner": "dion"
    },
    "device": {
      "hostname": "PK-RDNA2"
    },
    "network": {
      "neighbors": []
    },
    "software": []
  }'
```

Verify the latest stored inventory submission:

```sh
curl http://localhost:8000/api/v1/collectors/inventory/latest
```

Verify MVP-normalized assets and collectors:

```sh
curl http://localhost:8000/api/v1/assets
curl http://localhost:8000/api/v1/collectors
```

Asset normalization is intentionally minimal for now. The backend preserves the
raw inventory submission, then creates or updates basic collector records,
local-device assets, network-neighbor assets, IP observations, and
open_detector software detections for the local device. It does not perform
complex reconciliation, deduplication, service normalization, findings, or
enrichment yet.
