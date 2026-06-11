# OpenAssetWatch Collector

Standalone local collector for OpenAssetWatch asset discovery.

The collector is intentionally independent from the backend. It does not upload
results yet; it only writes normalized JSON to stdout.

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

## Backend Check-In

The collector can optionally send a lightweight manual check-in to the backend.
This does not upload full inventory and does not require authentication in the
MVP.

```sh
openassetwatch-collector --mode hybrid --checkin \
  --backend-url http://localhost:8000 \
  --collector-id local-dev-collector-01 \
  --collector-name "Local Dev Collector"
```

## Modes

- `device`: collects local host identity, OS/platform details, primary IP, and
  MAC address.
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
