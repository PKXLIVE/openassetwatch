# Experimental External AI Support Integration

## Purpose

This document preserves a possible future support path for OpenAssetWatch without changing the core product architecture or expanding the current implementation scope.

The idea is to evaluate an external agent runtime together with a portable memory service as an optional operator-support environment. The initial candidates are OpenClaw as the agent runtime and PLUR as the assistant memory layer.

This is an experimental integration concept, not a committed dependency, product requirement, or replacement for the OpenAssetWatch AI Advisor.

## Decision Summary

OpenAssetWatch may evaluate OpenClaw and PLUR through a small, isolated proof of concept when the project is ready.

They must remain outside the core OpenAssetWatch trust boundary:

```text
OpenAssetWatch Core
  |-- Collectors
  |-- Normalized Assets
  |-- Evidence and Findings
  |-- Policies
  |-- Read-Only Tool Gateway or API
              |
              v
Optional External Support Environment
  |-- OpenClaw Operator Assistant
  `-- PLUR Assistant Memory
```

OpenAssetWatch remains the source of truth. OpenClaw acts only as an external client, and PLUR stores support-oriented assistant memory rather than authoritative security evidence.

## Why This May Be Useful

A constrained external assistant could improve usability and reduce repeated support effort without requiring OpenAssetWatch to build a new memory architecture now.

Potential support functions include:

- explaining installation and configuration steps
- answering questions from project documentation
- summarizing collector health through approved read-only tools
- listing stale, unknown, or unmanaged assets
- generating sanitized reports
- remembering an operator's preferred report format
- remembering terminology, workflow, and presentation preferences
- preserving previously resolved support questions
- helping maintainers navigate project documentation and development conventions

The integration is useful only if it accelerates the existing roadmap rather than creating a competing platform inside OpenAssetWatch.

## Separation of Responsibilities

### OpenAssetWatch Core

OpenAssetWatch owns and remains authoritative for:

- asset inventory
- collector submissions
- normalized records
- observations and evidence
- deterministic findings
- risk calculations
- tenant and policy boundaries
- audit records
- approval controls
- AI-generated findings stored by OpenAssetWatch

### OpenClaw

OpenClaw may provide:

- an operator-facing conversational assistant
- session and workflow orchestration
- approved communication channels
- calls to explicitly allowlisted OpenAssetWatch tools
- presentation and summarization of read-only results

OpenClaw must not become the OpenAssetWatch Control Plane, evidence store, policy engine, or source of truth.

### PLUR

PLUR may store assistant-oriented memory such as:

- preferred report style
- terminology preferences
- documentation notes
- previously resolved support questions
- project workflow conventions

PLUR must not be treated as authoritative for:

- asset identity
- compromise status
- finding severity
- vulnerability state
- collector health
- tenant ownership
- security policy decisions

Any important claim recalled from assistant memory must be verified against current OpenAssetWatch evidence before it is presented as a fact or used in a recommendation.

## Initial Proof-of-Concept Scope

The first experiment should be an **OpenAssetWatch Support Assistant** operating against a lab or demo environment.

```text
User Question
     |
     v
OpenClaw
     |
     v
Approved Read-Only Tools
  |-- Search Documentation
  |-- Get Environment Summary
  |-- List Collector Health
  `-- Generate Sanitized Report
     |
     v
Operator Response

PLUR Stores Only
  |-- Reporting Preferences
  |-- Terminology Preferences
  |-- Resolved Support Questions
  `-- Project Workflow Conventions
```

The proof of concept should use synthetic or explicitly sanitized data. It should not require changes to collectors, normalization, the Control Plane, the evidence schema, or the existing AI Advisor roadmap.

## Required Security Boundary

### Allowed

- separate container, virtual machine, or isolated host
- synthetic or sanitized demonstration data
- read-only OpenAssetWatch API or Tool Gateway access
- dedicated low-privilege service identity
- explicitly allowlisted tools
- reviewed skills and extensions only
- complete logging of external assistant requests and tool calls
- PLUR memory limited to support context and user preferences
- manual disablement and full removal without data migration

### Prohibited

- direct database access
- direct Redis or message-bus access
- access to collector enrollment or authentication tokens
- arbitrary shell access
- unrestricted host filesystem access
- active scanning or packet capture
- collector policy changes
- firewall, endpoint, or network changes
- unreviewed community skills or extensions
- automatic ingestion of all conversations, raw evidence, or tenant data
- storage of passwords, tokens, credentials, private keys, or hashes
- writing recalled memory back as confirmed OpenAssetWatch evidence
- writing AI conclusions back as deterministic findings
- silent outbound messaging or external data sharing
- bypassing the OpenAssetWatch Tool Gateway or approval model

## Tool Access Model

External assistants should never call internal services or databases directly.

```text
External Assistant
       |
       v
OpenAssetWatch Tool Gateway
       |
       +-- Authentication
       +-- Authorization
       +-- Tenant Scope
       +-- Tool Allowlist
       +-- Input Validation
       +-- Output Redaction
       +-- Rate Limits
       `-- Audit Logging
               |
               v
         Read-Only Service
```

Every exposed tool should declare:

- purpose
- read-only status
- required role
- tenant scope
- permitted input fields
- redacted output fields
- rate limits
- audit behavior

The external assistant must receive no broader privileges than a normal user performing the same approved operation.

## Memory and Evidence Boundary

The most important design rule is that assistant memory and product evidence remain separate.

```text
OpenAssetWatch Evidence
  = authoritative, current, source-linked, tenant-scoped

External Assistant Memory
  = helpful context, preferences, support history, non-authoritative
```

A memory record may influence presentation or workflow convenience. It must not override current evidence, deterministic rules, tenant policy, authorization, or approval controls.

Example of acceptable assistant memory:

```yaml
statement: Use the technical report format for weekly summaries.
type: preference
domain: openassetwatch.reporting
```

Example of unacceptable authoritative use:

```yaml
statement: Asset 123 is compromised.
type: security_fact
```

Compromise claims and similar security conclusions belong in OpenAssetWatch's evidence and finding system, with provenance, timestamps, confidence, and tenant boundaries.

## Evaluation Criteria

Continue beyond the proof of concept only if it demonstrates:

- easier operator support
- less repeated setup and troubleshooting work
- accurate answers grounded in OpenAssetWatch data
- clean separation between memory and evidence
- acceptable resource usage
- complete auditability
- no Tool Gateway bypass
- no weakening of tenant isolation
- no required redesign of collectors or the Control Plane
- complete removal without migration or data-loss concerns

Stop or reject the integration if it requires:

- duplicating OpenAssetWatch inventory or findings in PLUR
- treating external assistant memory as a source of truth
- allowing direct database access
- granting broad system or network permissions
- weakening tenant, policy, or approval boundaries
- maintaining competing copies of evidence
- restructuring the OpenAssetWatch roadmap around either dependency
- making OpenClaw or PLUR mandatory for normal product operation

## Dependency and Lifecycle Position

OpenClaw and PLUR should be treated as optional adapters or integrations.

They are not:

- core runtime dependencies
- required deployment components
- replacements for the AI Advisor
- replacements for OpenAssetWatch evidence storage
- requirements for collectors or passive discovery
- prerequisites for local or air-gapped operation

Their versions, licenses, security posture, maintenance activity, and integration behavior must be reviewed again before any implementation begins. An integration may be paused, replaced, or removed without changing the OpenAssetWatch core architecture.

## Recommended Timing

Do not implement this integration during the current architecture and core-platform buildout unless a small support experiment can be completed without delaying committed milestones.

Revisit it when all of the following are true:

- a stable read-only OpenAssetWatch API or Tool Gateway exists
- authentication and tenant scoping are enforced
- useful documentation search is available
- sanitized demo data is available
- the experiment has a named owner and a time-boxed scope
- removal criteria are agreed upon before installation

## Final Position

OpenClaw and PLUR may provide a useful external support function, but only when kept isolated, optional, read-only, and subordinate to OpenAssetWatch's evidence and policy controls.

The integration should help users and maintainers reach the existing OpenAssetWatch goals faster. It must not create a second source of truth, introduce a new required memory architecture, or redirect the product roadmap.