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

**Implementation status:** `fabric gateway <registry-dir>` runs the inline admission point. It serves an HTTP endpoint that takes one interaction request (the agent, the model and prompt it intends to run, the tools it intends to use, and the input content it intends to send) and admits or blocks it *before* the interaction proceeds — 200 when admitted, 403 with a reason otherwise. Two checks compose, first denial wins: the registry check decides whether the agent may act at all (the pure `internal/gateway.Decide` core — the agent is registered, the prompt and every tool are ones it declares, and the model it asks to call is the one it is qualified for), and the content guardrail (`--guardrail <policy-file>`) decides whether this request's input may pass — a set of named regexp rules, in Git and reviewed like any other policy, that block input matching a sensitive-data or prohibited-content pattern (for example an exposed credential). The model allow-list screens the model a request *declares* against the agent's pinned model; a request that declares no model is not model-screened (the gateway screens what the caller asserts, and the post-hoc trace-evidence path re-derives this same decision without a model). `Decide` is the *same* qualified-surface judgment the interaction tracer makes after the fact: `evidence.FromAgentTraces` delegates to it, so a request the gateway blocks on registration is exactly a trace that rolls up as not-satisfied — one definition of "qualified", enforced at request time and re-confirmed in evidence. Output is screened too, not just input: a generated output posted to `/output` is run through the same guardrail (200 when it may pass, 403 when a rule catches it), so the policy applies on both sides of the interaction. Every handled interaction — input admission and output screening alike — is appended to a log (`--log <path>`) in the JSON-lines shape the trace producer consumes directly, recording the verdict but never the raw input or output (which may be the sensitive data a guardrail caught), so what the gateway enforced becomes control evidence with no separate collection step. The network shell (`ListenAndServe`) is the only part outside the test-first core; the decision, the model allow-list, the guardrail, and the input/output log shape are unit-covered. Still to come for a production gateway: enforcing the allow-list and guardrails on *live* LLM/MCP traffic by proxying the model and tool calls (today the gateway screens what each request declares rather than intercepting the wire), and rate and cost limits.

## Agent and prompt/tool registry

Prompts, tool definitions, retrieval configuration, and runtime policy are code. They live in Git and deploy from a versioned artifact. Each agent has a registry entry that pins the exact versions in production. A prompt change is a pull request with a diff and an approval, and a regression can be rolled back to a previous version. This gives the agent the same change control as any other regulated component.

**Implementation status:** the `internal/registry` package models agents, prompts, and tools as versioned artifacts (`<root>/agents`, `prompts`, `tools` JSON trees, the same layout as the OSCAL controls tree), and `fabric registry validate <registry-dir>` checks the registry for internal consistency: every artifact is versioned, every agent has an accountable owner, every prompt and tool an agent references resolves to a registered artifact, and no id is duplicated. A starter registry lives under `registry/`. The registry is the qualified surface the interaction tracer judges runtime behavior against.

## Guardrails and evaluation gates

Before an agent version reaches production it passes evaluation gates: checks for sensitive-data leakage, prompt-injection resistance, and output quality against a fixed test set. Guardrails run again at runtime on live traffic. A version that fails a gate does not promote.

**Implementation status:** the `internal/eval` package models the gate as authoritative promotion policy — which evaluation suites must have been run and how many failing cases are tolerated — kept separate from the run it judges, so a run cannot grade itself. `fabric eval-gate <eval-run-file> <gate-file> <control-id>` is the fifth evidence producer: it runs an agent version's evaluation results through the gate and records the verdict, satisfied when the version would promote and not-satisfied when the gate blocks it (a required suite went untested, or failures exceeded the budget). Records key to the `eu-ai-act-15-accuracy-robustness` control (implemented by a non-Kyverno `eval-gate` component) and feed the same ledger, so promotion decisions roll up through `fabric ledger assess` and `fabric ledger posture` like every other evidence source.

## Interaction tracing

Every agent action is traced with OpenTelemetry: the input, the model and version, the tools called, the retrieved sources, the output, and the policy decisions along the way. This produces a who, what, when, and why record for each action, which is the agent's audit trail. Traces flow into the evidence ledger like any other evidence.

**Implementation status:** `fabric trace <traces-json-file> <registry-dir> <control-id>` is the fourth evidence producer. It reads a gateway interaction log (one trace per interaction: the agent, the prompt it used, the tools it invoked, the timestamp) and judges each interaction against the registry's qualified surface — an interaction is satisfied only when the agent is registered and used only its declared prompt and tools, while an unregistered agent or any undeclared prompt or tool is off-policy (not-satisfied). It accepts three interaction-log shapes — the batch `{"traces":[...]}` envelope, the inline gateway's JSON-lines log, and the OpenTelemetry OTLP/JSON trace export (`{"resourceSpans":[…]}`) — so both the gateway's own record of what it enforced and a standard OTel trace pipeline are consumable as evidence with no reshaping. In the OTLP shape each span is one interaction: its attributes (`id`, `agent`, `prompt`, `tools`, and the gateway's recorded `allowed` verdict) mirror the JSON-lines field names, and the span's `startTimeUnixNano` is the observed time — so the same interaction is faithful whether it arrives as a gateway log line or an OTel span. The judgment is shared with the inline gateway through `internal/gateway.Decide` — the after-the-fact trace and the at-request-time block are the same decision. Records key to the `eu-ai-act-12-record-keeping` control (implemented by a non-Kyverno `agent-gateway` component) and feed the same ledger, `--ledger <path>` to append, so agent behavior rolls up through `fabric ledger assess` and `fabric ledger posture` like every other evidence source.

## Regulatory fit

This layer produces what the AI rules ask for:

- EU AI Act Article 11 technical documentation and post-market monitoring records, for high-risk uses whose obligations apply from August 2026.
- ISO 42001 records for an AI management system: inventory, risk, and monitoring.
- NIST AI RMF coverage across its Govern, Map, Measure, and Manage functions.
- Evidence for the AI-specific expectations in the draft EU GMP Annex 22.
