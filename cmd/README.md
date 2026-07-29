# Commands

This directory contains Go entrypoints for the future OpenAssetWatch runtime.
They are foundation commands, not complete product services yet.

- `oaw-agent`: local endpoint agent for passive local inventory and heartbeat
  work. It should not launch scanners or execute arbitrary commands.
- `oaw-sensor`: passive sensor entrypoint for approved metadata sources. Sensor
  mode is separate from agent mode and remains passive-first. Use `profile`,
  `demo`, `live`, `validate`, and `status` subcommands; replay mode is the
  cross-platform demonstration path.
- `oaw-cli`: operator CLI shell for future administrative workflows.
- `oaw-server`: future Go control-plane/API server entrypoint. The existing
  Python/FastAPI backend remains the current MVP server.
- `oaw-mcp-stdio`: future MCP stdio bridge for safe, scoped OAW data access.
- `oaw-test-config`: local config validation utility. It refuses quarantined
  config paths and validates safe OAW runtime config shape.
