# Passive Network Sensor MVP

OpenAssetWatch's passive network sensor is a Linux-first spoke that observes
metadata from a SPAN or mirror port and sends normalized evidence to the
existing hub observation-batch API. It is intentionally passive: it does not
scan, probe, inject packets, fetch discovered URLs, or upload raw packet data.
Production-oriented enrollment and per-sensor credential binding are
documented in `docs/SENSOR_ENROLLMENT.md`. Hardened systemd deployment,
bounded diagnostics, and the authorized SPAN workflow are documented in
`docs/SENSOR_LINUX_DEPLOYMENT.md`.

The sensor keeps the hub authoritative. The spoke may report an asset identity,
protocol evidence, VLAN scope, timestamps, and confidence. Risk, findings,
management state, policy, remediation, and AI conclusions are calculated by
the hub and are never assigned locally.

## Architecture

```text
capture.Source (synthetic replay or Linux AF_PACKET)
        |
        v
bounded Ethernet/VLAN and protocol decoders
        |
        v
site + MAC + VLAN correlation and TTL expiry
        |
        v
strict observation-batch contract
        |
        v
private durable spool -> authenticated outbound hub client
        |
        v
Control Tower assets, evidence, freshness, and AI Advisor tools
```

The capture interface is isolated behind `internal/sensor/capture.Source`.
Synthetic replay is available on every development platform and does not need
root, a network interface, Npcap, libpcap, or Internet access. Linux live mode
uses a bounded AF_PACKET receive loop and requires the minimum packet-capture
capabilities granted by the deployment administrator.

## Supported protocols

The MVP decodes bounded metadata from Ethernet, 802.1Q VLAN tags, ARP,
DHCPv4, DNS, mDNS, SSDP, and NetBIOS Name Service. IPv6 Neighbor Discovery
and LLDP are documented follow-ups. The decoder rejects truncated, malformed,
oversized, or excessively nested input and detects DNS compression loops.

SSDP `LOCATION` values are untrusted evidence only. The sensor never follows
or fetches them. Hostnames, service names, banners, and URLs are length-limited
and sanitized before they can reach the spool or hub.

## Replay demonstration

The deterministic replay path uses generated synthetic Ethernet frames only.
It exercises ARP, VLAN, DHCPv4, DNS, mDNS, SSDP, and NBNS through the same
decoder, correlation, spool, and hub client used by live mode:

```text
go run ./cmd/oaw-sensor demo \
  --hub-url http://127.0.0.1:8000 \
  --site-id demo-passive-site \
  --sensor-id sensor-passive-demo-01 \
  --spool-dir <user-writable-state-directory>
```

Enroll the sensor first or set `OPENASSETWATCH_SENSOR_CREDENTIAL` to an issued
bound credential. `OPENASSETWATCH_COLLECTOR_TOKEN` remains an explicitly
configured local-development compatibility mode, not the preferred production
path. The command prints a bounded summary and uses a deterministic batch
identifier, so replaying the same observation is idempotent at the hub.
The fixture uses a fixed historical observation timestamp; freshness views may
therefore label the replay-created asset evidence as stale while the sensor
itself is healthy from its current hub acknowledgement.
Use `oaw-sensor status --config <path>` for local configuration and credential
readiness. `oaw-sensor health --config <path>` reads the service's persisted,
bounded operational status. Neither exposes token values. Replay and live
commands print bounded runtime health counters.

The command surface is intentionally small:

```text
go run ./cmd/oaw-sensor version
go run ./cmd/oaw-sensor profile --site-id example-site
go run ./cmd/oaw-sensor config validate --config <path>
go run ./cmd/oaw-sensor interface list
go run ./cmd/oaw-sensor interface validate --interface enp2s0
go run ./cmd/oaw-sensor status --config <path>
go run ./cmd/oaw-sensor health --config <path>
go run ./cmd/oaw-sensor spool status --config <path>
go run ./cmd/oaw-sensor capture-check --interface enp2s0 --duration 30s
go run ./cmd/oaw-sensor demo --hub-url http://127.0.0.1:8000 --site-id demo-passive-site --sensor-id sensor-passive-demo-01
go run ./cmd/oaw-sensor service run --config <path>
```

## Configuration and identity

`oaw-sensor config validate --config <path>` validates the strict JSON sensor config.
The config contains site and sensor identity, hub URL, capture mode/interface,
identity path, separate credential path, spool path, batching, retry, and
aggregation limits. Bound credentials are read from the protected credential
file or `OPENASSETWATCH_SENSOR_CREDENTIAL`. Replay can still select an explicit
development shared-token environment with `--token-env`. Secret values are not
serialized into non-secret config, spool entries, health output, or logs.

Example Linux service configuration:

```json
{
  "hub_url": "https://hub.example.test",
  "site_id": "example-site",
  "sensor_name": "Example Passive Sensor",
  "capture_mode": "live",
  "capture_interface": "enp2s0",
  "identity_path": "/var/lib/openassetwatch/sensor/identity.json",
  "credential_path": "/var/lib/openassetwatch/sensor/credential.json",
  "spool_path": "/var/lib/openassetwatch/sensor/spool",
  "status_path": "/var/lib/openassetwatch/sensor/status.json",
  "credential_env": "OPENASSETWATCH_SENSOR_CREDENTIAL",
  "token_env": "OPENASSETWATCH_COLLECTOR_TOKEN",
  "batch_size": 250,
  "batch_interval_seconds": 60,
  "request_timeout_seconds": 10,
  "retry_initial_seconds": 2,
  "retry_max_seconds": 300,
  "spool_max_items": 1000,
  "spool_max_bytes": 268435456,
  "aggregation_max_devices": 2048,
  "aggregation_ttl_seconds": 1800
}
```

Identity is generated once and reused. On POSIX systems the identity and spool
root must be owned by the service account and must not grant group/other access.
The config file receives ownership, regular-file, single-link, and
path-replacement checks; the private root and relevant parent receive
directory ownership and permission checks before use. Identity files are
created once with exclusive creation and restrictive permissions. Windows
uses the repository's platform-safe rooted path handling but does not claim
POSIX owner or hard-link semantics; full Windows ACL provisioning is not part
of this MVP. Windows deployments should use a dedicated service account and
an administrator-created ACL-protected state directory.
Future native Windows sensor packaging should reuse the agent installer's
explicit Administrators/SYSTEM/service-identity ACL model rather than relying
on the standalone CLI to infer permissions.

## Spool and delivery

Only normalized JSON batches enter the spool. Writes use randomized temporary
files in the same directory, `fsync`, and atomic rename. Entries are delivered
oldest first, removed only after an `accepted` or `duplicate` hub acknowledgement,
and retried with capped exponential backoff and jitter for network, timeout,
429, and 5xx failures. 400/422 validation errors and 401/403 authentication
failures are permanent and are reported without token or response-body leakage.
The queue has item, byte, entry, retry, and incrementally bounded directory-scan
limits. The absolute queue and scan ceiling is 10,000 entries; the default is
1,000. Overflow is visible in health state rather than silently expanding disk
use. Quarantined corrupt entries remain normalized JSON only and require
operator inspection or removal.

The hub URL must use HTTPS except for explicit local development hosts
(`localhost`, `127.0.0.1`, `::1`, and `host.docker.internal` where local Compose
requires it). Redirects, URL userinfo, query strings, fragments, link-local
addresses, and cloud metadata endpoints are rejected. The client uses explicit
connect, TLS handshake, response-header, and overall request timeouts.
The per-sensor credential is bound and independently revocable but remains a
bearer value; it does not attest a sensor's machine identity.
Certificate-bound production enrollment and stronger impersonation resistance
remain follow-up work.

## Linux live capture

Use `oaw-sensor service run --config <path>` through the committed systemd unit
on a Linux host whose explicitly configured interface receives a SPAN or
mirror-port feed. The service runs as `openassetwatch-sensor` with only
`CAP_NET_RAW`; `CAP_NET_ADMIN` is not required by the sensor read loop. The
sensor exposes no inbound management or metrics listener. See
`docs/SENSOR_LINUX_DEPLOYMENT.md` for installation, `capture-check`, repair,
upgrade, removal, and authorized physical validation.

Docker Desktop on Windows and macOS does not provide a transparent path to a
physical host SPAN port. Use replay mode for demonstrations there, or run the
Linux sensor on the host or a dedicated Linux VM connected to the mirror port.

SNMP remains a separate, explicitly enabled active connector and is not part of
this passive sensor.

## Privacy and limitations

Packet bytes are transient decoder input only. They are never logged, spooled,
uploaded, or exposed to the AI worker. The AI Advisor receives normalized hub
evidence and bounded freshness/health metadata; it cannot access packet capture,
the sensor filesystem, shell commands, or sensor configuration.

Accepted passive evidence is projected into source-aware durable
classification evidence and queues evaluation only for affected assets. The
hub classifier may infer reviewed categories from DHCP, mDNS, SSDP, and NBNS,
but packet strings remain untrusted data. OUI establishes only a manufacturer,
and no SSDP URL is fetched. Current classification, conflicts, findings, and
risk remain hub-authoritative; AI is explanation-only.

The MVP correlates conservatively by site, normalized MAC, and optional VLAN.
IP addresses are time-bounded evidence and hostnames are supporting evidence,
not permanent identity keys. IPv6 Neighbor Discovery, LLDP, certificate-bound
enrollment, full native service packaging, and optional active SNMP integration
are planned follow-ups.

## Maintainer validation

The replay path is safe to run on Windows, macOS, or Linux and never selects a
real interface:

```text
go test ./internal/sensor/... ./cmd/oaw-sensor
go vet ./...
go test ./...
docker compose config
docker compose up -d --build postgres backend
go run ./cmd/oaw-sensor demo --hub-url http://127.0.0.1:8000 --site-id demo-passive-site --sensor-id sensor-passive-demo-01
```

Run the demo command twice to exercise hub idempotency. The resulting site,
sensor, asset, and bounded evidence are visible through
`/api/v1/hub/sites/summary`, `/api/v1/hub/sensors`, and
`/api/v1/control-tower/assets`. The deterministic AI provider can then answer
through `/api/v1/ai/advisor/query` without granting packet, filesystem, shell,
or sensor-management access.
