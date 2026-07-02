# OpenAssetWatch AI Advisor Architecture Visual

This companion page points to the visual architecture artifact for the AI
Advisor. The canonical architecture plan remains
`docs/architecture/ai-agent-architecture.md`.

## Visual artifact

- SVG export:
  `docs/architecture/assets/openassetwatch-ai-advisor-architecture.svg`
- HTML wrapper:
  `docs/architecture/assets/openassetwatch-ai-advisor-architecture.html`

The visual covers:

- Control Tower as the hub/coordinator
- collectors, passive sensors, integrations, `open_detector`, MCP tools, and
  AI modules as spokes
- the Shared Evidence Blackboard as the source of truth for AI-readable
  evidence context
- collection-to-AI data flow
- AI Advisor modules and the Reviewer / Evaluator gate
- trust boundaries for untrusted collector data, hostnames, banners, software
  names, network observations, notes, integration output, and tool output
- read-only/advisory AI defaults
- blocked unsafe actions such as scans, command execution, policy changes,
  device isolation, and secret collection
- future MCP access through the AI Tool Gateway and Control Tower only

## Figma note

A Figma design file named `OpenAssetWatch AI Advisor Architecture` was created,
but repository-derived architecture content was not written into Figma in this
run. A clean Figma export can be added later from the local SVG/HTML artifact
or from a separately approved design handoff.
