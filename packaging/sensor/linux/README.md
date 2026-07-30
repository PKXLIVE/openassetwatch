# OpenAssetWatch Passive Sensor Linux Deployment Source

This directory contains the committed, reviewable Linux deployment source for
the passive sensor:

- `systemd/oaw-sensor.service`: hardened non-root service unit
- `examples/sensor.example.json`: secret-free live configuration example

The distinct sensor service, account, binary, configuration, and state paths
must not be combined with the endpoint-agent package. The repository installer
at `scripts/release/install_sensor_linux.py` consumes the unit and validates
the fixed filesystem layout, service identity, capability allowlist, atomic
file replacement, lifecycle preservation, and explicit purge boundary.

The current deliverable is the verified installer and systemd lifecycle. DEB
and RPM packages remain a follow-up and must use a distinct sensor package
identity.
