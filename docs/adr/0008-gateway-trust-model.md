# ADR 0008: The gateway's trust model and how an agent proves its identity

## Status

Accepted.

## Context

ADR 0007 makes the gateway the mandatory control point for agent traffic. Every gate it applies — registry qualification, the model and tool allow-lists, and the rate and cost budget — is keyed on **which agent is calling**.

The gateway learns that from the `X-Fabric-Agent` request header. A header is a claim, not a credential. As originally shipped, any peer that could reach the listener could send `-H "X-Fabric-Agent: release-reviewer"` and inherit that agent's entire qualified surface and its budget. The identity that every enforcement decision depends on was the one thing never checked.

Two questions were conflated and need separating:

1. **Who may talk to the gateway at all?** A network question.
2. **May this caller act as this agent?** An identity question.

Answering only (1) — "the listener is on a trusted network" — is a legitimate deployment posture, but it was never written down, so an operator had no way to know it was load-bearing. Nothing in the code or the docs said the listener must not be publicly reachable.

## Decision

**Authenticate the asserted agent identity before any gate keyed on it runs**, and make the trust posture explicit rather than implied.

- The proxy takes an optional `AgentTokens` map from agent id to a shared secret. When it is configured, a request must present a matching `X-Fabric-Token`; the comparison is constant-time, and a missing, unknown, or wrong credential is `401` before the registry, guardrail, or limiter sees the request.
- When `AgentTokens` is **not** configured, the agent header remains an unauthenticated assertion. This is a supported posture for a gateway reachable only over loopback or behind an mTLS sidecar that terminates client certificates — but it is now a documented, deliberate choice, stated on the field itself.
- A failed authentication is logged as a denied interaction, so impersonation attempts appear in the evidence ledger rather than vanishing.

Shared secrets are the floor, not the ceiling. They were chosen because the project is stdlib-only and a secret per agent is deployable anywhere. Where the platform already issues workload identity, an mTLS client certificate bound to the agent id is strictly better: it needs no shared state, it rotates with the platform's own machinery, and it cannot leak through a log or an environment dump.

## Consequences

- The gateway's guarantees are no longer contingent on an unstated network assumption. An operator can read the trust boundary off the code.
- Enforcement is only as strong as credential distribution. A shared secret leaked into a log, an image layer, or a CI variable is a full impersonation of that agent, so tokens belong in the same secret store as any other deployment credential and should be rotated on the same schedule.
- A constant-time comparison prevents recovering a token by timing, but nothing here defends against a caller that legitimately holds one agent's token and abuses that agent's own qualified surface. That remains the registry's and the guardrail's job.
- The unauthenticated mode is retained deliberately: forcing tokens on a loopback-only development gateway would push operators toward disabling the proxy entirely, which is worse. The default is convenience; the documented posture makes it a choice.
- Interactions re-derived after the fact from a trace are **not** authenticated — there is no live caller to challenge. Post-hoc evidence therefore attests what the gateway recorded, not that the identity was proven at the time; a trace from a gateway running without tokens inherits that weaker claim.
