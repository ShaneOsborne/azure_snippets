# Known Limitations and Why Manual Review Is Still Required

These scripts are designed to **support discovery, prioritization, and manual review** for the Azure Data Factory managed identity + trusted services firewall bypass retirement scenario. They are intended to reduce blind spots and focus engineering effort, but they are **not designed to provide definitive proof of runtime impact**.

The reason is that this scenario depends on a combination of factors that are **not always visible from static metadata alone**, including:

- Whether a linked service is actually used by active pipelines
- Whether a target endpoint is resolved dynamically at runtime
- Whether managed identity is truly the authentication path in use
- Whether the target resource is actually relying on trusted services bypass
- Whether the configuration belongs to a live production workload or only exists as legacy, test, or unused configuration

---

## What the Scripts Can Do Reliably

The scripts are effective at **correlating available control-plane metadata** across Azure Data Factory, Azure Resource Graph, Storage accounts, and Key Vaults. In practice, they can reliably surface:

- Factories with system-assigned or user-assigned managed identity
- Linked services and integration runtimes
- Common Storage and Key Vault target patterns
- Trusted services firewall bypass configuration
- Parameterized or unresolved targets that need deeper inspection
- Conservative confidence signals to help prioritize review effort

This makes the scripts **useful for estate-wide discovery and triage**, especially where manually inspecting every factory would be impractical.

---

## Known Limitations

### Best-effort managed identity detection

Managed identity usage is inferred primarily from linked service `authenticationType`. Some connectors may use MI implicitly or via properties not surfaced consistently. **Results indicate likelihood, not proof.**

### Incomplete target resolution

Target URIs are derived from common fields only (`url`, `baseUrl`, `serviceEndpoint`). Parameterized or implicit targets may not resolve at discovery time and are flagged for manual review.

### Name-based inventory matching

`targetInventoryMatch` is based on matching derived hostnames to Storage or Key Vault names. This does not account for:

- Private endpoints
- DNS aliases
- Custom domains
- Runtime redirection

### No pipeline or activity inspection

Pipelines, activities, datasets, and expressions are not inspected. Scenarios such as REST, Web, Azure Function, or parameterized linked services may require follow-up analysis.

### Conservative, advisory classification

`riskLevel` and stage-2 confidence values are **prioritization aids only**. They should not be treated as definitive impact assessments or compliance attestations.

### Non-exhaustive connector coverage

Only common Storage and Key Vault–related linked service types are explicitly recognized. Unrecognized connectors may require manual interpretation.

### Subscription-scoped visibility

Discovery relies on Azure Resource Graph visibility in the scanned subscriptions. Cross-tenant or externally hosted targets are not validated.

---

## Why This Cannot Be Fully Automated

Even with improvements such as inventory matching, confidence scoring, and parameterized target detection, the scripts do not inspect:

- Pipeline definitions
- Activity-level behavior
- Dataset bindings
- Runtime parameter values
- Trigger-driven variations
- Environment-specific overrides
- Whether a linked service is currently unused

Because of that, some rows may still represent:

**False positives** – configurations that look relevant but are not actually exercised at runtime

**False negatives** – cases where the real target or authentication path is only visible through dynamic expressions or activity-level logic

A **human reviewer can inspect runtime intent and architectural context** in ways that static analysis cannot. In particular, manual review can confirm:

- Whether the linked service is referenced by live pipelines
- Whether parameterized endpoints resolve to Storage or Key Vault at runtime
- Whether managed identity is truly the execution path being used
- Whether another supported network path is already in place
- What the real remediation priority is for the workload

---

## Recommended Interpretation

These scripts should be treated as **decision-support tools, not automated proof engines**.

The intended operating model is:

1. **Stage 1** – Use `Get-AdfTrustedBypassRiskReport.ps1` to identify broad candidates.

2. **Stage 2** – Use `Get-AffectedServices.ps1` to reduce the result set into likely affected or manual-review rows.

3. **Human validation** – Inspect pipelines, activities, and runtime design where needed before deciding whether remediation is required.

This allows **automation to do what it does best** — scale discovery and reduce blind spots — while leaving **final confirmation to engineering review** where runtime behavior is dynamic or context-dependent.
