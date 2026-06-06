# AI agent governance

This is the layer that separates the Fabric from generic compliance tooling. It puts an AI agent into a regulated environment with the controls, traceability, and evidence a quality team and an auditor require.

## The core problem

An AI agent is non-deterministic. The same input can produce different actions. Validation and audit assume you can describe and reproduce system behavior, so the agent has to be bounded and recorded tightly enough that its behavior is accountable even when it is not fixed.

The Fabric does this with four components.

## AI and MCP gateway

All agent traffic to models and tools passes through one gateway. Nothing reaches a model or calls a tool outside it. The gateway enforces:

- An allow-list of models and tools per agent.
- Policy on inputs and outputs, including blocking of sensitive data.
- Rate and cost limits.
- A complete record of every call.

Routing all traffic through one boundary is what makes the rest of the controls possible.

## Agent and prompt/tool registry

Prompts, tool definitions, retrieval configuration, and runtime policy are code. They live in Git and deploy from a versioned artifact. Each agent has a registry entry that pins the exact versions in production. A prompt change is a pull request with a diff and an approval, and a regression can be rolled back to a previous version. This gives the agent the same change control as any other regulated component.

**Implementation status:** the `internal/registry` package models agents, prompts, and tools as versioned artifacts (`<root>/agents`, `prompts`, `tools` JSON trees, the same layout as the OSCAL controls tree), and `fabric registry validate <registry-dir>` checks the registry for internal consistency: every artifact is versioned, every agent has an accountable owner, every prompt and tool an agent references resolves to a registered artifact, and no id is duplicated. A starter registry lives under `registry/`. The registry is the qualified surface the interaction tracer judges runtime behavior against.

## Guardrails and evaluation gates

Before an agent version reaches production it passes evaluation gates: checks for sensitive-data leakage, prompt-injection resistance, and output quality against a fixed test set. Guardrails run again at runtime on live traffic. A version that fails a gate does not promote.

## Interaction tracing

Every agent action is traced with OpenTelemetry: the input, the model and version, the tools called, the retrieved sources, the output, and the policy decisions along the way. This produces a who, what, when, and why record for each action, which is the agent's audit trail. Traces flow into the evidence ledger like any other evidence.

**Implementation status:** `fabric trace <traces-json-file> <registry-dir> <control-id>` is the fourth evidence producer. It reads a gateway interaction log (one trace per interaction: the agent, the prompt it used, the tools it invoked, the timestamp) and judges each interaction against the registry's qualified surface — an interaction is satisfied only when the agent is registered and used only its declared prompt and tools, while an unregistered agent or any undeclared prompt or tool is off-policy (not-satisfied). Records key to the `eu-ai-act-12-record-keeping` control (implemented by a non-Kyverno `agent-gateway` component) and feed the same ledger, `--ledger <path>` to append, so agent behavior rolls up through `fabric ledger assess` and `fabric ledger posture` like every other evidence source.

## Regulatory fit

This layer produces what the AI rules ask for:

- EU AI Act Article 11 technical documentation and post-market monitoring records, for high-risk uses whose obligations apply from August 2026.
- ISO 42001 records for an AI management system: inventory, risk, and monitoring.
- NIST AI RMF coverage across its Govern, Map, Measure, and Manage functions.
- Evidence for the AI-specific expectations in the draft EU GMP Annex 22.
