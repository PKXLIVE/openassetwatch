# Local Development

Start the local stack:

```sh
docker compose up -d
```

Check backend health:

```sh
curl http://localhost:8000/health
```

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
