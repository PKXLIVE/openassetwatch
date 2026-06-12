# OpenAssetWatch Collector

Standalone local collector for OpenAssetWatch asset discovery.

The collector can run fully standalone and write normalized JSON to stdout. It
can also optionally send lightweight check-ins or full inventory uploads to the
backend when explicitly configured.

## Usage

Run commands from the repository root.

On macOS/Linux:

```sh
PYTHONPATH=collector python -m openassetwatch_collector --mode device --pretty
PYTHONPATH=collector python -m openassetwatch_collector --mode network --pretty
PYTHONPATH=collector python -m openassetwatch_collector --mode hybrid --pretty
```

On PowerShell:

```powershell
$env:PYTHONPATH = "collector"
python -m openassetwatch_collector --mode device --pretty
python -m openassetwatch_collector --mode network --pretty
python -m openassetwatch_collector --mode hybrid --pretty
```

## Editable Install

Install the collector locally from the `collector` directory:

```sh
cd collector
python -m pip install -e .
openassetwatch-collector --mode device --pretty
openassetwatch-collector --mode network --pretty
openassetwatch-collector --mode hybrid --pretty
```

## Tests

Run collector unit tests from the repository root:

```sh
PYTHONPATH=collector python -m unittest discover collector/tests
```

## Backend Check-In

The collector can optionally send a lightweight manual check-in to the backend.
This reports collector health and heartbeat metadata only. It does not upload
full inventory and does not require authentication in the MVP.

```sh
openassetwatch-collector --mode hybrid --checkin \
  --backend-url http://localhost:8000 \
  --collector-id local-dev-collector-01 \
  --collector-name "Local Dev Collector"
```

## Inventory Upload

Inventory upload sends the full collector payload to the backend, including
device details, network discoveries, and `open_detector` software detections.
It is separate from check-in: `--checkin` sends a lightweight heartbeat, while
`--upload-inventory` sends the full inventory payload. If both are provided,
the collector sends the check-in first, then uploads inventory.

```sh
openassetwatch-collector --mode hybrid --upload-inventory \
  --backend-url http://localhost:8000 \
  --collector-id local-dev-collector-01 \
  --collector-name "Local Dev Collector"
```

## Scheduled Mode

Scheduled mode runs continuously. It performs an initial check-in and inventory
upload on startup, then sends a collector check-in every hour and uploads full
inventory every 24 hours by default. Backend errors are reported and the
scheduler keeps running.

```sh
openassetwatch-collector --mode hybrid --run-forever \
  --backend-url http://localhost:8000 \
  --collector-id local-dev-collector-01 \
  --collector-name "Local Dev Collector"
```

Override intervals from the CLI:

```sh
openassetwatch-collector --mode hybrid --run-forever \
  --backend-url http://localhost:8000 \
  --collector-id local-dev-collector-01 \
  --heartbeat-interval-seconds 3600 \
  --inventory-interval-seconds 86400
```

For local smoke testing, use short intervals:

```sh
openassetwatch-collector --mode hybrid --run-forever \
  --backend-url http://localhost:8000 \
  --collector-id local-dev-collector-01 \
  --heartbeat-interval-seconds 10 \
  --inventory-interval-seconds 20
```

For local install planning, see `docs/setup/collector-deployment.md`. The
collector remains Python-first: Windows uses Task Scheduler at startup for the
MVP, Linux uses systemd, and macOS uses the LaunchDaemon at
`/Library/LaunchDaemons/com.openassetwatch.collector.plist`.

Packaging is future scope. MSI/EXE, DEB/RPM, macOS PKG, optional DMG wrapping,
and signing/notarization are not implemented in the installer-hardening PR.

For local multi-machine installer testing, see
`docs/setup/local-collector-installation.md`. For reinstall/uninstall
validation scenarios, see `docs/setup/collector-installer-test-matrix.md`.

## Config File

The collector can load backend and collector settings from a YAML or JSON config
file. CLI arguments override config values.

Run without config:

```sh
openassetwatch-collector --mode device --pretty
openassetwatch-collector --mode network --pretty
openassetwatch-collector --mode hybrid --pretty
```

Example YAML:

```yaml
collector:
  id: local-dev-collector-01
  name: Local Dev Collector
  mode: hybrid

backend:
  url: http://localhost:8000

checkin:
  enabled: true

inventory:
  upload_enabled: true

scheduler:
  enabled: false
  heartbeat_interval_seconds: 3600
  inventory_interval_seconds: 86400
```

Run with config:

```sh
openassetwatch-collector --config ./example-collector.yaml --checkin
```

Send a backend check-in using config:

```sh
openassetwatch-collector --config ./example-collector.yaml --checkin
```

Send a full inventory upload using config:

```sh
openassetwatch-collector --config ./example-collector.yaml --upload-inventory
```

Run scheduled mode using config:

```sh
openassetwatch-collector --config ./example-collector.yaml --run-forever
```

Override the configured mode from the CLI:

```sh
openassetwatch-collector --config ./example-collector.yaml --mode device --pretty
```

## Open Detector

Device and hybrid modes include a `software` section generated by
`open_detector`, the collector's passive local software detection framework.
It looks for evidence of security, endpoint, management, observability,
container, and VPN/ZTNA tools using safe checks such as known commands, known
install paths, and short version output where available.

`open_detector` does not collect secrets, read credential stores, query remote
APIs, start or stop services, require administrator privileges, or modify the
host. Detections are evidence-based and include confidence levels so downstream
features can distinguish strong signals from best-effort hints.

## Modes

- `device`: collects local host identity, OS/platform details, primary IP, and
  MAC address, plus passive local software detections.
- `network`: collects local ARP/neighbor table entries and normalizes IP, MAC,
  interface, state, and source.
- `hybrid`: runs both device and network collection.

Use `--pretty` for indented output. Without `--pretty`, the collector emits
compact JSON for scripts and pipelines.

## Platform Capabilities

Every mode includes a `platform` section describing the collector host:
operating system, architecture family, ARM/64-bit flags, available discovery
commands, missing discovery commands, supported collector modes, and safe future
fingerprinting tool categories.

This is host capability detection only. Target asset fingerprinting, aggressive
Nmap scans, passive packet capture, sensor mode, and backend upload are not
implemented yet.
