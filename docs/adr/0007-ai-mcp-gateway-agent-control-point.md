# ADR 0007: A single AI/MCP gateway as the agent control point

## Status

Accepted (reference design).

## Context

An AI agent is non-deterministic: the same input can produce different actions. Validation and audit assume system behavior can be described, bounded, and reproduced. To make an agent accountable even when its behavior is not fixed, every model call and tool invocation must be constrained and recorded at a point that cannot be bypassed.

## Decision

Route all agent traffic to models and tools through one mandatory AI/MCP gateway. Nothing reaches a model or calls a tool outside it. The gateway enforces a per-agent allow-list of models and tools, policy on inputs and outputs (including sensitive-data blocking), and rate and cost limits, and it records every call. Traces flow into the evidence ledger like any other evidence.

## Consequences

- A single boundary is what makes the other agent controls possible: guardrails, interaction tracing, and the agent/prompt registry all hang off it.
- Every agent action gets a who/what/when/why record, which is the agent's audit trail and feeds EU AI Act, ISO 42001, and NIST AI RMF evidence.
- The gateway is a high-value trust boundary and a potential single point of failure, so it must be operated for availability and protected like the build pipeline's identity.
- Agents must be prevented, by platform policy, from reaching models or tools by any path that bypasses the gateway.
