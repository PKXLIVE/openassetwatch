# AI Advisor Agent Architecture

## Purpose

The OpenAssetWatch AI Advisor helps users understand asset inventory, network
observations, software and security tooling coverage, enrichment data, and risk
findings.

The AI Advisor should provide value after OpenAssetWatch has collected,
normalized, enriched, and scored data. It should not replace collector logic,
normalization, deterministic detection rules, or rule-based risk scoring.
Instead, it should explain what OpenAssetWatch already knows, highlight gaps,
prioritize next steps, and produce evidence-backed summaries and reports.

## User Value

The AI Advisor should eventually help users answer questions such as:

- What devices are on my network?
- Which assets look unmanaged?
- Which devices expose risky services?
- Which hosts are missing EDR, MDM, logging, or vulnerability agents?
- Which devices look like IoT, OT-like, embedded, printers, cameras, or
  appliances?
- Which assets changed recently?
- Which devices should be segmented?
- What should I fix first?
- Why is this asset risky?
- Generate an executive summary.
- Generate a technical remediation report.
- Suggest Splunk searches or dashboard ideas.

These answers should be grounded in OpenAssetWatch evidence rather than broad
model guesses. The AI should help users move from raw visibility to clear,
prioritized action.

## Advisory-First Principle

The AI Advisor is advisory first.

The AI may:

- explain
- summarize
- prioritize
- recommend
- generate reports
- suggest validation steps

The AI must not automatically:

- change firewall rules
- modify endpoints
- change collector configuration
- run active scans
- start packet capture
- execute shell commands
- exploit systems
- collect credentials

Any future workflow that could affect systems, networks, collectors, or users
must require explicit human approval and must pass through narrowly scoped
safety controls.

## Evidence-First Principle

Every AI Advisor answer should be grounded in OpenAssetWatch evidence.
Relevant evidence may include:

- asset records
- network observations
- collector metadata
- software and security tooling detections
- vulnerability enrichment
- CMDB or identity enrichment
- policy and capability context
- timestamps
- source references

AI output should include evidence references wherever practical, such as asset
IDs, collector IDs, observation timestamps, software detection evidence,
finding IDs, source systems, and confidence levels. When evidence is weak,
missing, or indirect, the AI should say so plainly.

## Safety Principles

The AI Advisor should follow these safety principles:

- read-only by default
- no arbitrary remote commands
- tenant isolation
- secrets redaction
- tool allowlists
- capability checks
- license and entitlement checks in the future
- human approval for high-impact actions
- audit logging for AI decisions and tool use

The AI Advisor should treat OpenAssetWatch as a visibility and decision-support
platform, not as an autonomous remediation system. Safety and policy controls
must sit between AI reasoning and any future tool use.

## Text Architecture Diagram

```text
OpenAssetWatch Data
-> Evidence Layer
-> AI Advisor / Agent Orchestrator
-> Specialist Agents
-> Tool Gateway
-> Safety and Policy Layer
-> Reports and Recommendations
```

The Evidence Layer should assemble normalized assets, observations, findings,
enrichment records, timestamps, and source references. The AI Advisor / Agent
Orchestrator should route questions and tasks to constrained specialist agents
when useful. The Tool Gateway should expose only approved, read-only or
human-approved actions. The Safety and Policy Layer should enforce tenant
isolation, capability boundaries, redaction, entitlement, and audit behavior.

## Out of Scope

The following are out of scope for this PR:

- AI runtime implementation
- model or provider integration
- MCP server implementation
- autonomous scanning
- exploit tools
- packet capture
- credential collection
- active network changes
