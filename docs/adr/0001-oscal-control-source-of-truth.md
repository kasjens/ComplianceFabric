# ADR 0001: OSCAL as the control source of truth

## Status

Accepted (reference design).

## Context

The Fabric needs one representation of controls that authoring, enforcement, and assessment can all share. Without a common format, the mapping from a control to its policy and back to its evidence is manual and breaks under change.

## Decision

Use OSCAL as the machine-readable source of truth for controls, profiles, and assessment results. Author controls in OSCAL catalogs and profiles. Express control-to-policy mappings as OSCAL component definitions. Collect engine results as OSCAL assessment results.

## Consequences

- A control can be traced forward to the policy that implements it and the evidence that satisfies it, and backward from any assessment result.
- Compliance-to-Policy can generate policy for multiple engines from one mapping.
- The format is a NIST standard, so it is stable and tool-supported.
- Authors need OSCAL fluency. The control library becomes a maintained asset, which is acceptable because that library is also the product's main IP.
