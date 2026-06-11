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
