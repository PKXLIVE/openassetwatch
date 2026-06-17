# Docker Installer Scaffold

This compose file is a packaging scaffold for the future Go-based OAW server.
It does not install offensive tools, scanners, payload generators, or credential
testing utilities.

Set secrets outside the compose file:

```bash
export OAW_POSTGRES_PASSWORD="set-this-outside-git"
docker compose -f installers/docker/docker-compose.yml up -d
```

The current root `docker-compose.yml` remains the local development stack for
the existing Python/FastAPI MVP.
