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

Inventory persistence stores raw collector submissions in Postgres and performs
minimal MVP normalization into collector, asset, IP observation, and software
detection records.

Send a collector heartbeat/check-in:

```sh
curl -X POST http://localhost:8000/api/v1/collectors/checkin \
  -H "Content-Type: application/json" \
  -d '{
    "collector_id": "local-dev-collector-01",
    "collector_name": "Local Dev Collector",
    "hostname": "PK-RDNA2",
    "collector_version": "0.1.0",
    "mode": "hybrid",
    "platform": {
      "system": "windows",
      "architecture": "amd64"
    },
    "status": "healthy",
    "message": "manual smoke test"
  }'
```

Send a collector inventory payload:

```sh
curl -X POST http://localhost:8000/api/v1/collectors/inventory \
  -H "Content-Type: application/json" \
  -d '{
    "schema_version": "0.1",
    "collector": {
      "id": "local-dev-collector-01",
      "name": "Local Dev Collector"
    },
    "collector_version": "0.1.0",
    "mode": "hybrid",
    "platform": {
      "system": "windows",
      "architecture": "amd64"
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
