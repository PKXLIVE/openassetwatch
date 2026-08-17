# Linux Passive Sensor Deployment and SPAN Validation

This guide deploys the OpenAssetWatch passive network sensor as a hardened
Linux systemd service and validates it on a switch SPAN or mirror destination
that the operator owns or is authorized to monitor. It does not authorize
monitoring third-party traffic.

The service runs as `openassetwatch-sensor`, not root. Systemd grants only
`CAP_NET_RAW`, which the current AF_PACKET implementation needs to open its
passive socket. The sensor does not request `CAP_NET_ADMIN`, change
promiscuous mode or link state, add addresses, routes, or bridges, or transmit
discovery traffic. A mirror destination commonly needs promiscuous mode so its
NIC does not discard mirrored unicast frames; that remains an explicit
operator-controlled host-networking action rather than a sensor privilege.

Physical SPAN validation has not been performed as part of the repository test
suite. The installer, filesystem lifecycle, service definition, Linux build,
and deterministic replay are testable without a physical mirror port. Follow
the bounded procedure below on an authorized Linux capture host.

## Deployment model

Use two interfaces when practical:

```text
management interface                    dedicated capture interface
DHCP/static address, DNS, HTTPS          switch mirror destination
          |                                         |
          v                                         v
OpenAssetWatch hub <--- outbound batches --- oaw-sensor AF_PACKET
```

The management interface carries DNS and outbound HTTPS to the hub. The
capture interface receives copied frames from the switch. Avoid DHCP, an IP
address, a default route, bridging, bonding, or outbound applications on the
capture-only interface when practical. OpenAssetWatch does not configure the
interface; the operator remains responsible for the host and switch.

A mirror source is the port or VLAN whose traffic is copied. A mirror
destination is the dedicated switch port connected to the sensor capture
interface. Vendor-specific switch syntax varies and is not a universal part of
this guide. Confirm the switch documentation, direction (ingress, egress, or
both), oversubscription behavior, and authorization before enabling mirroring.

## Supported Linux targets

The installer is intended for systemd-based Debian, Ubuntu, Raspberry Pi OS,
RHEL, Rocky Linux, AlmaLinux, and Fedora hosts. The current sensor is pure Go
and supports the Linux architectures accepted by the repository build,
including amd64 and arm64. Raspberry Pi installations should prefer a current
64-bit OS where possible and must verify that the installed systemd version
accepts every hardening directive:

```text
systemd-analyze verify /etc/systemd/system/oaw-sensor.service
```

Docker Desktop on Windows or macOS does not transparently expose a physical
host SPAN port to a Linux container. Use deterministic replay there. Use a
dedicated Linux host or VM with direct access to the capture NIC for physical
validation.

## Filesystem and service identity

| Purpose | Path | Owner | Mode |
| --- | --- | --- | --- |
| Binary | `/usr/bin/oaw-sensor` | `root:root` | `0755` |
| Configuration directory | `/etc/openassetwatch/sensor` | `root:openassetwatch-sensor` | `0750` |
| Configuration | `/etc/openassetwatch/sensor/sensor.json` | `root:openassetwatch-sensor` | `0640` |
| Private state | `/var/lib/openassetwatch/sensor` | `openassetwatch-sensor:openassetwatch-sensor` | `0700` |
| Stable identity | `/var/lib/openassetwatch/sensor/identity.json` | service identity | `0600` |
| Bound credential | `/var/lib/openassetwatch/sensor/credential.json` | service identity | `0600` |
| Durable normalized spool | `/var/lib/openassetwatch/sensor/spool` | service identity | `0700` |
| Operational status | `/var/lib/openassetwatch/sensor/status.json` | service identity | `0600` |
| Service unit | `/etc/systemd/system/oaw-sensor.service` | `root:root` | `0644` |

The account is a locked system account with a non-interactive shell and is
never UID 0. Configuration remains root-controlled but readable by the service
group. Identity, credential, spool, and status remain service-private.

Configuration and private-state readers reject unsafe owners, modes, symlinks,
non-regular files, multiply linked files where the platform exposes link
counts, writable parents, and path replacement during open. Installer writes
use randomized same-directory temporary names, `fsync`, and atomic
replacement. The installer writes no privileged log beneath service-writable
storage; ordinary runtime output goes to journald.

## Build and install

Build from a reviewed commit and stage the ELF binary in a root-controlled
location:

```text
go build -trimpath -o oaw-sensor ./cmd/oaw-sensor
sudo install -o root -g root -m 0755 ./oaw-sensor /root/oaw-sensor-install
```

Review the fixed-path plan. `--dry-run` does not modify the host:

```text
sudo python3 scripts/release/install_sensor_linux.py \
  --dry-run \
  install \
  --binary /root/oaw-sensor-install \
  --hub-url https://hub.example.test \
  --site-id example-site \
  --interface enp2s0
```

Install the binary, root-controlled configuration, private state layout, and
unit:

```text
sudo python3 scripts/release/install_sensor_linux.py \
  install \
  --binary /root/oaw-sensor-install \
  --hub-url https://hub.example.test \
  --site-id example-site \
  --interface enp2s0
```

Installation validates the ELF source and records its SHA-256 in bounded JSON
output. It creates or validates the locked service account, fixed paths,
owners, modes, capability allowlist, unit, and config. It runs
`oaw-sensor config validate` as the unprivileged service account and
`systemd-analyze verify` before `daemon-reload` or activation. A new install is
enabled but not started by default so enrollment can complete first. Pass
`--start` only when a valid bound credential already exists.

The installer never accepts enrollment tokens or sensor credentials.

## Configuration and interface selection

The generated configuration is strict JSON. It requires `capture_mode` set to
`live` and an explicit `capture_interface`; live mode never chooses all
interfaces, the first interface, the default-route interface, or the
management interface.

List bounded interface metadata without opening a capture socket:

```text
sudo -u openassetwatch-sensor \
  /usr/bin/oaw-sensor interface list
```

Inspect operating-system counters and confirm the selected link:

```text
ip -details link show dev enp2s0
ip -s link show dev enp2s0
```

Validate existence, link state, MAC address, capture suitability, and effective
capability state without starting capture:

```text
sudo systemd-run --quiet --wait --pipe --collect \
  --property=User=openassetwatch-sensor \
  --property=Group=openassetwatch-sensor \
  --property=NoNewPrivileges=yes \
  --property=CapabilityBoundingSet=CAP_NET_RAW \
  --property=AmbientCapabilities=CAP_NET_RAW \
  /usr/bin/oaw-sensor interface validate --interface enp2s0
```

The interface MAC is diagnostic metadata only. IP addresses and packet
contents are not emitted by interface inspection.

On Linux, the output also includes `promiscuous` and `promiscuous_known`. If
the interface is up and non-loopback but promiscuous mode is off, validation
warns that the NIC may filter mirrored unicast frames. After confirming the
correct dedicated capture interface and an authorized maintenance window, an
administrator can enable it explicitly:

```text
sudo ip link set dev enp2s0 up
sudo ip link set dev enp2s0 promisc on
```

Make the setting persistent through the host's existing network-management
configuration. Do not assign DHCP or static addresses, a default route, a
bridge, or forwarding to the capture-only interface unless the authorized
topology specifically requires it. The sensor only reads and reports the
state; neither `interface validate`, `capture-check`, nor `service run`
reconfigures the interface.

Validate the installed config:

```text
sudo -u openassetwatch-sensor \
  /usr/bin/oaw-sensor config validate \
  --config /etc/openassetwatch/sensor/sensor.json
```

## Enrollment

Create a one-time enrollment token through the authenticated hub
administration workflow described in `docs/SENSOR_ENROLLMENT.md`. Do not place
the token in a command argument, unit, environment file, shell history,
installer output, or journald.

Run enrollment as the service identity and use the bounded standard-input
path. Paste or pipe the token from a protected operator workflow:

```text
sudo -u openassetwatch-sensor \
  /usr/bin/oaw-sensor enroll \
  --config /etc/openassetwatch/sensor/sensor.json \
  --enrollment-token-stdin
```

The one-time token is exchanged for a site-, sensor-ID-, and sensor-type-bound
credential. The credential is written atomically to the private credential
file and is never printed. Verify only non-secret status:

```text
sudo -u openassetwatch-sensor \
  /usr/bin/oaw-sensor credential-status \
  --config /etc/openassetwatch/sensor/sensor.json
```

## Bounded capture check

Stop the long-running service before testing the same interface:

```text
sudo systemctl stop oaw-sensor.service
```

Run an explicitly bounded 30-second diagnostic under the service identity with
only `CAP_NET_RAW`:

```text
sudo systemd-run --quiet --wait --pipe --collect \
  --property=User=openassetwatch-sensor \
  --property=Group=openassetwatch-sensor \
  --property=NoNewPrivileges=yes \
  --property=PrivateTmp=yes \
  --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property=CapabilityBoundingSet=CAP_NET_RAW \
  --property=AmbientCapabilities=CAP_NET_RAW \
  /usr/bin/oaw-sensor capture-check \
  --interface enp2s0 \
  --duration 30s
```

The allowed duration is one second through five minutes. The command does not
upload, persist packets, print packet bytes, retain DNS history, send traffic,
fetch SSDP URLs, or reconfigure the interface. It reports only:

- frames observed, decoded, malformed, and rejected
- per-protocol frame counts
- VLAN IDs
- bounded candidate-device count
- requested and effective duration
- interface and effective capability state

Recheck `ip -s link show dev enp2s0`. A mirror destination with zero received
frames may indicate the wrong interface, inactive link, switch configuration,
or no traffic at the selected source. Resolve that outside OpenAssetWatch; the
sensor does not probe or generate test traffic.

## Start and verify

Start the hardened service:

```text
sudo systemctl start oaw-sensor.service
sudo systemctl --no-pager --full status oaw-sensor.service
```

Read bounded persisted health and spool state:

```text
sudo -u openassetwatch-sensor \
  /usr/bin/oaw-sensor health \
  --config /etc/openassetwatch/sensor/sensor.json

sudo -u openassetwatch-sensor \
  /usr/bin/oaw-sensor spool status \
  --config /etc/openassetwatch/sensor/sensor.json
```

Review secret-free runtime messages:

```text
sudo journalctl -u oaw-sensor.service --since -15min --no-pager
```

In the authenticated Control Tower, verify the sensor identity, last check-in,
asset evidence, protocol evidence, VLAN scope, freshness, and queued/retried
delivery state. Ask the AI Advisor a site-scoped question and verify that its
answer cites normalized sensor evidence. The Advisor has no raw-packet,
filesystem, credential, capture, shell, or sensor-management access.

## Restart and recovery

The service uses `Restart=on-failure`, a ten-second delay, and bounded start
limits. A missing interface creates bounded degraded status and exits; systemd
retries without a rapid loop, and capture can resume after the interface
returns. Authentication rejection remains a bounded hub error while normalized
batches stay queued for operator action.

Identity, credential, status, and queued batches survive service and host
restart. Only hub-acknowledged batches are removed. Retry delays are capped,
spool item and byte limits remain enforced, and corrupt normalized entries are
quarantined. Raw frames never enter the spool.

## Repair, upgrade, uninstall, and purge

Repair with a reviewed replacement build:

```text
sudo python3 scripts/release/install_sensor_linux.py \
  repair \
  --binary /root/oaw-sensor-install
```

Upgrade uses the same validation and preservation path:

```text
sudo python3 scripts/release/install_sensor_linux.py \
  upgrade \
  --binary /root/oaw-sensor-next
```

Repair and upgrade quiesce an active service, replace the binary and unit
atomically, preserve config, identity, credential, and spool, validate before
activation, and restart only if the service was already active or `--start`
was supplied. A failed transaction restores previous managed files and attempts
to restore the prior active service.

Normal uninstall removes the service unit and binary but deliberately preserves
configuration, identity, credential, status, and spool:

```text
sudo python3 scripts/release/install_sensor_linux.py uninstall
```

Explicit purge permanently removes the service files, configuration, identity,
credential, status, spool, and dedicated account:

```text
sudo python3 scripts/release/install_sensor_linux.py \
  purge \
  --confirm-purge
```

Purge stops and disables the service first, validates fixed paths, atomically
quarantines the private trees under root-controlled parents, and then removes
them. Do not use purge when offline evidence or identity continuity must be
retained.

To roll back an authorized mirror-port validation without uninstalling, stop
the service and disable the mirror session on the switch. If this guide's
temporary host setting is no longer needed by another authorized capture
consumer, return the dedicated interface to non-promiscuous mode:

```text
sudo systemctl stop oaw-sensor.service
sudo ip link set dev enp2s0 promisc off
```

## Systemd hardening and capability rationale

The committed unit uses:

- non-root `User=` and `Group=`
- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `ProtectSystem=strict` and `ProtectHome=true`
- kernel tunable, module, and control-group protection
- SUID/SGID, personality, executable-memory, namespace, and IPC restrictions
- `UMask=0077`
- explicit read-only config and writable state paths
- address families limited to local IPC, DNS/HTTPS networking, netlink, and
  AF_PACKET
- `CapabilityBoundingSet=CAP_NET_RAW`
- `AmbientCapabilities=CAP_NET_RAW`

`CAP_NET_RAW` is required for the existing `socket(AF_PACKET, SOCK_RAW, ...)`
call. `CAP_NET_ADMIN` is not required because the sensor does not request
promiscuous membership or change interface configuration. If promiscuous mode
is needed for the mirror destination, an administrator configures it outside
the service before capture begins. Capabilities are granted by systemd to the
verified root-owned binary rather than stored as permanent file capabilities.

## Passive-only and privacy guarantees

This branch adds no active discovery protocol or inbound management port. The
sensor performs:

- no ARP, ping, or port sweep
- no SNMP
- no service or banner probing
- no SSDP URL fetching
- no credential collection
- no packet-payload logging
- no raw-packet spool or upload
- no raw-packet access for the AI Advisor

Raw frame bytes exist only transiently during bounded decoding and are cleared
after use. DNS query history is not retained as device evidence.

## Validation status

Repository validation distinguishes simulation from physical validation:

- installer validation: completed in a Linux filesystem lifecycle harness
- service lifecycle validation: completed for unit, account plan, modes,
  preservation, rollback, uninstall, and purge; full systemd-as-PID-1 runtime
  depends on the validation host
- Linux live-capture compile validation: completed
- deterministic replay validation: completed
- physical SPAN validation: pending on an authorized Linux host

DEB and RPM sensor packages are not produced in this branch. The immediate
follow-up is to reuse the existing endpoint-agent package metadata and
lifecycle validation framework with the distinct package name, binary, service,
account, config, and state paths documented here.
