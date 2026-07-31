# Deterministic Findings and Risk

OpenAssetWatch treats deterministic findings and risk as authoritative Control
Tower data. The processing order is:

```text
normalized evidence
  -> deterministic asset classification and provenance
  -> reviewed deterministic finding rules
  -> persisted finding lifecycle
  -> deterministic asset and site risk
  -> read-only AI explanation
  -> human review
```

The AI Advisor is not part of finding detection or scoring. It cannot create,
score, resolve, acknowledge, or suppress a finding. It can only explain
persisted records and cite their finding IDs through the existing bounded
read-only tool gateway.

## Rule Registry

`backend/app/findings.py` contains one explicit `RULE_REGISTRY`. There is no
dynamic rule loading, expression evaluation, model-authored rule, or plugin
execution path. Collected values are untrusted data and cannot select code or
change a rule's severity.

The current ruleset is `oaw.findings.v2`. Classification semantics are owned
by `oaw.classifier.v1`; see
`docs/ASSET_CLASSIFICATION_AND_EVIDENCE_FUSION.md`.

| Rule | Subject | Trigger | Severity | Important boundary |
| --- | --- | --- | --- | --- |
| `sensor-stale` | sensor | An enrolled, non-revoked sensor has no authenticated check-in or exceeds the configured threshold. | medium | Uses authenticated enrollment/check-in state. |
| `asset-stale` | asset | Normalized `observed_at` exceeds the configured asset freshness threshold. | low | Stale evidence cannot resolve another finding. |
| `unknown-asset` | asset | The current deterministic classification is unknown or insufficient. | medium when new, otherwise low | Does not guess a category from hostname, address, OUI, or model output; classification confidence becomes finding confidence. |
| `passive-only-asset` | asset | A fresh class whose managed capability expects an endpoint collector currently has only passive evidence and no historical endpoint evidence. | low | IoT, printer, storage, camera, media, OT, and network-device classes do not trigger merely because they cannot run an endpoint collector. |
| `security-coverage-gap` | asset | Fresh endpoint-origin inventory explicitly says coverage is missing/degraded for a class whose managed capability expects endpoint security. | high | Missing fields, stale records, passive-sensor assertions, and not-expected classes are insufficient. |
| `identity-conflict` | asset | Two fresh, bounded same-site asset records share one valid unicast hardware-address correlation. | high | Hostname/IP equality plus malformed, all-zero, broadcast, and multicast addresses are ignored; finding evidence stores opaque references, not the address value. |
| `classification-conflict` | asset | Current deterministic category, OS, version, or role classification contains a material independent-source conflict. | medium | Uses only server-issued classification evidence IDs; AI cannot resolve or override the conflict. |

VLAN movement is deliberately deferred. The current normalized hub schema does
not retain a durable, structured VLAN history. Deriving movement from display
strings or a single latest observation would create false findings. Add this
rule only after the evidence contract and database preserve bounded VLAN
history with observation timestamps and source identity.

Severity expresses potential impact. Confidence expresses deterministic
evidence quality. They remain separate fields throughout evaluation, storage,
API output, UI rendering, and scoring.

## Finding Model and Lifecycle

Each finding has:

- stable `finding_id` and deterministic `dedupe_key`;
- rule ID/version and ruleset-linked evaluation run;
- category, subject type, site, and optional asset or sensor identity;
- bounded title, description, recommendation, severity, and confidence;
- evidence observation time and freshness;
- `active`, `acknowledged`, `suppressed`, or `resolved` lifecycle state;
- first/last seen, resolution, acknowledgement, suppression, and reopen audit
  fields; and
- up to eight normalized evidence references with source, time, freshness,
  confidence, and a bounded non-sensitive summary.

Re-running an unchanged rule updates the same finding. A resolved finding
reopens if the same deterministic condition returns. A missing candidate
resolves only when fresh evidence for that exact rule and subject affirmatively
proves the condition ended. For example, a coverage gap requires an explicit
healthy endpoint-origin status; a missing coverage field or passive observation
cannot resolve it. Identity conflicts do not auto-resolve because a
counterpart record disappearing is insufficient proof. Missing assets, missing
sensors, revoked identities, stale evidence, and failed collection do not
resolve findings. The current and previous rule versions plus the change time
remain visible on the logical finding. Acknowledgement records human review but
does not remove risk. Suppression is an audited admin action and excludes the
finding from risk while active. Expired suppression returns to active on the
next matching evaluation.

Evaluation failures are recorded without failing evidence ingestion. New
endpoint and observation evidence first queues targeted classification of only
affected assets. Semantic reclassification then queues targeted finding and
risk replacement. Sensor check-ins still use sensor scope and only the
sensor-health rule. Scope is pushed into indexed database reads, so a site
evaluation does not load every site's assets. Administrators can also run a
bounded sensor, site, asset, selected-rule, or full evaluation. The MVP
intentionally does not introduce a scheduler or external background-work
framework.

## Risk Formula

The formula version is `oaw.risk.v1`. Risk is always an integer from 0 to 100.

For each active or acknowledged asset finding:

```text
raw contribution =
  severity weight
  * deterministic confidence
  * evidence freshness factor
```

Default severity weights are critical 40, high 25, medium 14, low 7, and
informational 3. Freshness factors are fresh 1.0, aging 0.8, stale 0.45, and
unknown 0.35.

Within a category, contributions are ordered deterministically and multiplied
by 1.0, 0.6, 0.35, then 0.2 for the fourth and later findings. Category totals
are capped: identity 35, coverage 30, inventory 25, freshness 20, movement 20,
and other 20. The asset score is the capped sum of category contributions.
This prevents duplicate findings in one category from dominating the score.

A site is not a sum of all asset scores:

```text
asset portfolio =
  0.50 * highest asset score
  + 0.30 * nearest-rank 75th percentile
  + 0.20 * average of the ten highest asset scores
```

Direct site/sensor finding risk is combined against the portfolio's remaining
headroom at a 0.35 factor. The persisted factors expose each input,
intermediate weight, and adjusted contribution. Bands are minimal 0-14, low
15-34, moderate 35-59, high 60-79, and critical 80-100.

Environment overrides are bounded rather than open-ended:

- `OPENASSETWATCH_FINDINGS_SENSOR_STALE_MINUTES` (15 to 10080; default 120)
- `OPENASSETWATCH_FINDINGS_ASSET_STALE_HOURS` (1 to 720; default 72)
- `OPENASSETWATCH_FINDINGS_NEW_ASSET_HOURS` (1 to 168; default 24)
- `OPENASSETWATCH_FINDINGS_EVIDENCE_FRESH_HOURS` (1 to 168; default 24)
- `OPENASSETWATCH_FINDINGS_EVIDENCE_AGING_HOURS` (fresh threshold to 720; default 72)
- `OPENASSETWATCH_FINDINGS_MAX_CANDIDATES` (100 to 10000; default 10000)
- `OPENASSETWATCH_RISK_WEIGHT_<SEVERITY>` (0 to 60)
- `OPENASSETWATCH_RISK_CAP_<CATEGORY>` (0 to 60)

Invalid values fall back to reviewed defaults. Changing weights or thresholds
does not change rule code; review configuration changes like other security
policy.

## Additive Database Schema

Startup schema initialization adds:

- `finding_evaluation_runs`
- `findings`
- `finding_evidence`
- `asset_risk_scores`
- `site_risk_scores`
- `risk_factors`

The tables use typed columns, checks, foreign keys, unique deduplication, and
bounded query paths. Evidence and score explanation are normalized rows rather
than unbounded JSON. Findings do not foreign-key to revocable sensor
credentials, so historical records remain queryable after revocation.
Transaction-scoped PostgreSQL advisory locks serialize reconciliation and risk
replacement; monotonic evaluation-time guards prevent an older snapshot from
overwriting newer finding/risk state. Existing evidence tables are not changed
or dropped.

## Authenticated API

Read endpoints follow the existing local Control Tower convention: they enforce
`X-OpenAssetWatch-Admin-Token` when `OPENASSETWATCH_ADMIN_TOKEN` is configured.
State-changing finding endpoints fail closed with `503` when that secret is not
configured and require a constant-time token match when it is configured.

Read endpoints:

- `GET /api/v1/findings` with bounded site, asset, sensor, status, severity,
  rule, category, timezone-aware updated-time range, limit, and offset filters
- `GET /api/v1/findings/{finding_id}`
- `GET /api/v1/findings/rules`
- `GET /api/v1/risk/summary`
- `GET /api/v1/risk/assets/{asset_id}?site_id=...`
- `GET /api/v1/risk/sites/{site_id}`

Admin mutations:

- `POST /api/v1/admin/findings/evaluate`
- `POST /api/v1/admin/findings/{finding_id}/acknowledge`
- `POST /api/v1/admin/findings/{finding_id}/suppress`

Example full evaluation request:

```sh
curl -sS -X POST \
  -H "Content-Type: application/json" \
  -H "X-OpenAssetWatch-Admin-Token: ${OPENASSETWATCH_ADMIN_TOKEN}" \
  --data '{"requested_by":"local-admin"}' \
  http://127.0.0.1:8000/api/v1/admin/findings/evaluate
```

Asset and sensor scope require `site_id` and are mutually exclusive.
Sensor-scoped evaluation permits only the sensor-health rule. Rule selection is
an explicit bounded list of registered IDs. There is no endpoint for uploading
rule code.

## Demo and UI

The demo seed stores documentation-range addresses, locally administered MAC
addresses, and safe normalized evidence signals. It does not insert finding or
risk rows directly. After seeding, it runs the production deterministic
evaluator. The Office demo shows a stale sensor and unknown asset. The Lab demo
shows a fresh passive-only server, an explicit endpoint coverage gap, and a
safe same-site identity conflict. The seed also moves the Office unknown asset
through known and back to unknown using production evaluation, leaving the
same finding active with `reopen_count = 1`. Demo-owned evaluation history is
cleared on reseed, so repeated seeding is deterministic. VLAN movement remains
absent because the durable evidence contract does not support it.

The existing Findings view loads active and acknowledged persisted records. It
shows the reviewed title, severity, confidence, lifecycle state, subject,
remediation, evidence-reference count, first/last seen, and deterministic risk.
Finding/rule IDs, freshness, formula version, and bounded score factors remain
available under technical details. Site cards show the persisted site score.
When an admin token is configured, enter it in the existing AI Advisor token
field and refresh; the value remains page-local and is not stored.

## AI Boundary

`ReadOnlyHubTools` receives persisted classifications, classification evidence,
findings, and risk from PostgreSQL.
`findings_by_site`, `highest_risk_assets`, site summary, environment summary,
finding evidence citations, and bounded risk-factor explanations use those
records. Classification summary, asset classification/evidence/conflict,
unknown-category, managed-capability, and classification-confidence tools use
the same bounded read-only gateway. Model context identifies deterministic
records as authoritative. AI
output is explicitly
`advisory_only`, and responses identify
`deterministic-findings-risk-engine` as their authoritative source.

The provider prompt treats all collected values as untrusted data, rejects tool
selection by the model, and requires supplied evidence IDs. A provider cannot
invent a finding reference because unknown evidence IDs fail response
validation.

## Adding a Rule Safely

1. Confirm a normalized, durable, bounded evidence field exists.
2. Add a pure evaluator in `backend/app/findings.py`. Do not fetch networks,
   run commands, use dynamic expressions, or retain raw packets.
3. Add one `RuleDefinition` to `RULE_REGISTRY` with a new stable ID and version.
4. Use opaque evidence references and hard-coded bounded summaries. Do not put
   raw addresses, hostnames, packet bytes, credentials, or customer content in
   finding text.
5. Define resolution eligibility. If fresh evidence cannot prove the condition
   ended, do not auto-resolve it.
6. Add detection, negative, lifecycle, risk, API, adversarial-input, and
   performance tests.
7. Document the rule, severity, evidence source, false-positive boundary, and
   any new bounded configuration.
8. Review the complete diff and deterministic reproducibility before release.

## Validation

The backend lock targets Linux/Python 3.12 and is tested through Docker:

```sh
docker compose config
docker compose run --rm --no-deps --volume "${PWD}:/workspace" --workdir /workspace/backend backend python -m unittest discover -s tests -v
docker compose run --rm --no-deps --volume "${PWD}:/workspace" --workdir /workspace/backend backend python -m compileall -q app tests
docker compose run --rm --no-deps backend python -m pip check
docker build --tag openassetwatch-backend-lock-check backend
docker run --rm --entrypoint sh openassetwatch-backend-lock-check -c 'python -m pip install --disable-pip-version-check --no-cache-dir pip-audit==2.10.1 && python -m pip_audit --require-hashes --disable-pip -r /tmp/openassetwatch-requirements.txt'
docker compose --profile demo run --rm demo-seed
python scripts/test_control_tower_demo_seed.py
python scripts/test_control_tower_dashboard.py
```

Focused pure-engine coverage includes thousands of synthetic assets,
reproducibility, confidence/freshness effects, duplicate-category caps,
open/update/resolve/reopen behavior, stale-evidence non-resolution, API
authorization, and AI authority/citation behavior.

## Development Performance

On the Windows development host with Python 3.12.13, an in-memory synthetic
run over 10,000 assets across 25 sites produced 1,000 deterministic candidates
in 0.1055 seconds. Deterministic scoring of 10,000 assets with 30,000 open
finding inputs across the same 25 sites completed in 0.1759 seconds. These are
pure engine measurements, not PostgreSQL or HTTP benchmarks. Database inputs
are capped at 50,000 assets, 20,000 sensors, and 10,000 sites; candidate output
is capped at 10,000, reconciliation at 20,000 records, and API pages at 200.
Site scope is applied in SQL before loading. A production database/load test
remains necessary before raising any bound.

## Security Properties and Limits

- Rule code is reviewed and static; evidence cannot register or execute code.
- Queries and request models are bounded; unknown rules and invalid lifecycle
  values are rejected.
- Finding evidence stores opaque references and bounded summaries, never raw
  packets.
- Classification-conflict evidence cites server-issued `cev_...` references,
  not packet bytes or credential-bearing metadata.
- Evaluation performs no active scanning, URL fetching, SSRF-capable lookup,
  command execution, or arbitrary HTTP callback.
- Ingestion succeeds even when post-response evaluation fails; logs retain only
  the exception type, not arbitrary database or evidence text.
- Suppression and acknowledgement are explicit audited admin mutations that
  fail closed when admin authorization is not configured.
- Reconciliation and risk replacement are serialized, and stale concurrent
  snapshots cannot overwrite newer state.
- The current MVP runs post-response evaluations in-process. Large
  multi-tenant deployments will need a durable job mechanism, tenant-scoped
  authorization, migration tooling, retention policy, and operational metrics.
- Passive-only classification now uses durable, source-aware evidence and
  historical endpoint presence. A production retention policy and tenant model
  remain follow-ups before claiming complete enterprise management coverage.
- VLAN movement, exposed-service, vulnerability, patch, and configuration rules
  remain deferred until their required normalized evidence is durable and
  tested.
