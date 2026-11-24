# ADR-0007: Threat Intelligence Exchange Boundary

- **Status:** Accepted
- **Date:** 2026-08-28

## Context

OpenAssetWatch already defines provider-neutral connectors, canonical evidence ingress, external intelligence enrichment, governed external projections, AI trust labeling, sensitive-output validation, and adversarial-input evaluation. What remained missing was a dedicated contract for interoperable cyber-threat-intelligence exchange that could support discovery, scoped collections, object manifests, object versions, incremental synchronization, partial-processing receipts, and governed outbound publication without creating a parallel source of truth.

External intelligence also contains descriptive text that may eventually enter AI-assisted investigation. An authenticated exchange source therefore introduces two independent questions:

1. Was the source/transport authenticated and authorized?
2. Is the imported content safe, current, correct, and appropriate to treat as evidence or model context?

Those questions must not collapse into one trust decision.

## Decision

OpenAssetWatch accepts a future provider-neutral **Threat Intelligence Exchange Boundary** as a specialization of the existing Connector Gateway and External Projection architecture.

The design will:

- represent approved exchange endpoints through reviewed configuration;
- represent collections as scoped capability surfaces rather than authorization grants;
- enforce tenant, collection, object, and operation authorization separately;
- project inbound objects into OpenAssetWatch-owned envelopes;
- preserve source object IDs, versions, digests, freshness, provenance, and withdrawal state;
- support lightweight manifests and replay-safe incremental checkpoints;
- issue typed receipts for accepted, rejected, duplicate, pending, and partially processed objects;
- keep exchange ingestion non-authoritative for findings, risk, and vulnerability applicability;
- classify imported descriptive content as untrusted for AI purposes even when transport is authenticated;
- support optional heuristic preflight content classification only as a restrictive signal;
- enforce deterministic context-admission budgets before model processing;
- route outbound intelligence through sanitization, policy, evidence validation, approval when required, and a separate narrow publisher identity; and
- preserve local-first operation when exchange services are unavailable.

## Authority Order

```text
external exchange object
  -> authenticated/authorized transport
  -> bounded schema validation
  -> untrusted external intelligence envelope
  -> correlation candidate
  -> deterministic and/or human verification
  -> optional OpenAssetWatch finding/risk processing through existing rules
```

Outbound:

```text
verified OpenAssetWatch evidence
  -> share candidate
  -> sanitization and shareability policy
  -> approval when required
  -> narrow publisher
  -> external collection
```

AI does not own either authority transition.

## Security Invariants

- Source authentication cannot upgrade content into model instructions.
- A collection's technical read/write capability cannot grant a principal permission.
- Inbound `verified` and outbound `approved_for_sharing` are different states.
- Withdrawal of an external object cannot erase local evidence or automatically resolve findings.
- A successful network request cannot be treated as successful processing of every object.
- Schema-valid content remains subject to scope, provenance, semantic, and safety validation.
- External intelligence may trigger review but cannot prove compromise or vulnerability applicability by itself.
- AI agents may not publish directly to external exchange collections.
- Context classifiers may make treatment more restrictive but may not increase trust.
- External exchange transport is optional and replaceable.

## Integration With Existing Architecture

The exchange boundary extends rather than replaces:

- `connector-playbook-projection-architecture.md` for connector identity, credentials, checkpoints, ingress, and external projection;
- `external-intelligence-enrichment-roadmap.md` for non-authoritative external observations and correlation;
- `defensive-content-and-model-robustness.md` for sensitive-content inspection and current-intelligence handling;
- `ai-adversarial-input-and-injection-evaluation.md` for hostile-content and prompt-propagation tests; and
- `ai-agent-permission-output-security.md` for Safe Output Gate and separate publisher identity.

## Implementation Sequence

1. Define endpoint, collection, object-envelope, manifest, receipt, authorization, and context-admission contracts with synthetic fixtures.
2. Add one reviewed read-only inbound compatibility profile.
3. Add correlation, health visibility, and AI context-admission enforcement.
4. Add outbound sharing only after sensitive-content inspection, Safe Output, approval, and narrow publisher controls are available.
5. Add further compatibility profiles only through independent security, licensing, and operational review.

## Rejected Alternatives

OpenAssetWatch will not:

- import a reference server as the product's exchange authority;
- make an exchange storage backend canonical;
- use plaintext persisted exchange credentials;
- infer authorization solely from collection capability flags;
- accept arbitrary user-supplied exchange destinations;
- allow feed text to become AI policy;
- create authoritative findings directly from exchanged indicators;
- allow AI-direct publication; or
- make external intelligence exchange mandatory for core functionality.

## Consequences

### Positive

- Standardized intelligence exchange can be added without weakening the existing evidence model.
- Collection and object synchronization become auditable and replayable.
- Partial processing and withdrawal semantics remain visible.
- AI receives a clear trust boundary for external intelligence text.
- Future sharing can reuse existing Safe Output and publisher-identity controls.

### Cost

- The platform must maintain separate endpoint, collection, object, manifest, receipt, authorization, and publication states.
- Compatibility testing becomes protocol/profile specific.
- Bidirectional exchange requires additional privacy, licensing, and customer-shareability policy.

## Implementation Status

Architecture direction only. No threat-intelligence exchange server/client, protocol adapter, collection service, external credential, model classifier, or outbound publisher is implemented by this ADR.