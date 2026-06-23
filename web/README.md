# Web

Reserved for the OpenAssetWatch web application.

The first Control Tower dashboard is currently served from
`backend/app/static/index.html` through the local Compose `web` service at
`http://localhost:8080`. It focuses on sites, agents/sensors, check-ins,
assets, evidence counts, and release metadata status.

Future production UI work should continue toward richer asset inventory,
evidence, findings, remediation, and connector health views.
