# Control authoring

Controls are written as code in OSCAL and stored in Git. This is the single source of truth for what the platform must enforce and what evidence proves it.

## Why OSCAL

OSCAL is a NIST standard that expresses controls, profiles, and assessment results in machine-readable form. Using it means controls, the mapping to technical policy, and the assessment output share one format, so they can be processed and version-controlled like any other code.

The Fabric uses three OSCAL model types:

- Catalog: the full set of control statements for a framework.
- Profile: the selection and tailoring of controls that apply to a given system.
- Component definition: the mapping from controls to the technical policies that implement them.

## Repository layout

Controls live in their own repository, separate from application code.

```text
controls/
  catalogs/
    gamp5.json
    annex11.json
    cfr-part-11.json
    alcoa-plus.json
    dora.json
    nis2.json
    iso-42001.json
    eu-ai-act.json
  profiles/
    pharma-mes-baseline.json
    finance-trading-baseline.json
  component-definitions/
    kyverno.json
    sigstore.json
    gitops.json
    agent-gateway.json
```

## Control to policy mapping

A component definition names the controls a component satisfies and the policy identifiers that implement them. Compliance-to-Policy reads it and generates the policy for each engine. The shape of a mapping entry:

```json
{
  "control-id": "annex11-9-audit-trail",
  "description": "System generates a secure, time-stamped audit trail.",
  "implemented-by": [
    { "component": "platform-logging", "policy-id": "require-audit-logging" },
    { "component": "evidence-ledger", "policy-id": "append-only-storage" }
  ]
}
```

## Change control on the controls themselves

Changes to controls and mappings go through pull requests. The review and merge record becomes part of the audit trail: who proposed the change, who approved it, and when. The controls repository is therefore both the design record and a source of evidence.
