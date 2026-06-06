# ADR 0004: Open-core model under Apache 2.0

## Status

Accepted (reference design).

## Context

The project needs two things that pull in different directions. It needs community contribution, because a single founder cannot build and maintain control mappings across every framework alone. It also needs a revenue path, because the GxP control library and the validation-report generation are the parts that are hard to build and were identified as the product's intellectual property in `docs/10-build-vs-buy.md`.

A fully closed product loses the trust advantage that matters in compliance tooling and gets no community help. A fully permissive release with no commercial layer gives away the work that funds the project and leaves no way to sustain it.

## Decision

Adopt an open-core model. License the core under Apache 2.0: the framework, policy templates, OSCAL control mappings, integrations, and documentation. Keep a commercial layer separate, offered by the project's commercial sponsor: a hosted control plane, polished audit-pack and validation-report generation, certified GxP control packs, and enterprise support.

Use Apache 2.0 rather than a copyleft license because the goal is wide adoption and for the control mappings to become a shared reference. Apache 2.0 is the norm for the projects this builds on (Kubernetes, Kyverno, Sigstore, OSCAL Compass), which lowers friction for contributors and adopters.

## Consequences

- The control logic is open and inspectable, which is the trust signal that matters to quality teams and auditors.
- Community can contribute control mappings and integrations, which is how the project covers more frameworks than a solo effort could.
- The commercial layer funds continued development without closing the core. The boundary is stated in `GOVERNANCE.md` so contributors know what they are building.
- A permissive license allows others, including cloud providers, to host the open core. This is an accepted trade for adoption. If hosting by third parties becomes a real problem, a future ADR can revisit the license for new components.
- The open core builds the maintainers' visibility and authority on the method, which supports the project's long-term sustainability.
