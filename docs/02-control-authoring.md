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
  crosswalks/
    dora.json
    nis2.json
```

A crosswalk maps a target-sector citation (for example a DORA or NIS2 article) onto the controls the Fabric already enforces and evidences, so the same enforced control answers a second framework with no new enforcement. `fabric validate` checks each crosswalk's referential integrity against the catalogs — every anchor and target resolves to a real control, and no citation is mapped twice or to nothing — and `fabric crosswalk <crosswalk-file> <source-ledger>` rolls a ledger's existing evidence up under the mapped citations.

## Control to policy mapping

A component definition follows the OSCAL rule_set convention that Compliance-to-Policy consumes. A component declares its rules as grouped props — each rule set pairs a `Rule_Id` (the abstract rule) with a `Check_Id` (the automated check that enforces it, which for Kyverno is the policy name) — and each `implemented-requirement` binds a control to one or more rules by `Rule_Id`. C2P reads this and generates the policy for each engine. The shape:

```json
{
  "title": "kyverno",
  "type": "validation",
  "props": [
    { "name": "Rule_Id", "value": "audit-logging-annotation", "remarks": "rule_set_00" },
    { "name": "Check_Id", "value": "require-audit-logging-annotations", "remarks": "rule_set_00" }
  ],
  "control-implementations": [
    {
      "source": "controls/profiles/pharma-mes-baseline.json",
      "implemented-requirements": [
        {
          "control-id": "annex11-9-audit-trail",
          "description": "System generates a secure, time-stamped audit trail.",
          "props": [{ "name": "Rule_Id", "value": "audit-logging-annotation" }]
        }
      ]
    }
  ]
}
```

## Change control on the controls themselves

Changes to controls and mappings go through pull requests. The review and merge record becomes part of the audit trail: who proposed the change, who approved it, and when. The controls repository is therefore both the design record and a source of evidence.
