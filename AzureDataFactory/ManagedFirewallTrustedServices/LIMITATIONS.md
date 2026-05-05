# Known Limitations

These scripts are intentionally designed as a **two‑stage discovery and reduction workflow**. They trade completeness for safety and scalability, particularly in large or regulated environments. The following limitations are known and expected.

---

## 1. Best‑effort linked service managed identity detection

Managed identity usage is inferred primarily from linked service–level `authenticationType` values. Connector‑specific deep inspection of `typeProperties` is intentionally out of scope.

As a result:

- Some connectors may use managed identity implicitly or via properties not exposed in a consistent way.
- `usesManagedIdentity = Y` should be treated as **strong but not definitive** evidence.
- Missing or uncertain MI evidence may still require manual review in stage 2.

---

## 2. Target resolution may be incomplete

Target URIs are derived only from common fields such as:

- `url`
- `baseUrl`
- `serviceEndpoint`

Limitations include:

- Parameterized linked services may not expose a resolvable target at discovery time.
- Some connectors do not surface a clear endpoint suitable for hostname extraction.
- `targetDetectionStatus = Parameterized`, `NotFound`, or `Unknown` indicates incomplete resolution and should be reviewed manually if other signals are present.

---

## 3. Inventory matching is name‑based only

`targetInventoryMatch` is determined by matching the derived hostname to:

- Storage account names
- Key Vault names

This approach does not:

- Follow private endpoints
- Resolve DNS aliases
- Handle cross‑tenant or externally hosted endpoints
- Validate that the resolved target is the *intended* runtime target used by pipelines

A positive inventory match indicates **correlation**, not guaranteed runtime usage.

---

## 4. No pipeline or activity inspection

Neither script inspects:

- Pipelines
- Activities
- Dataset bindings
- Runtime expressions

Consequently:

- Actual runtime behavior is not validated.
- REST, Web, AzureFunction, and parameterized scenarios are flagged conservatively using `NeedsPipelineInspection`.
- Stage‑2 results should be treated as **likely affected or manual‑review candidates**, not proof of impact.

---

## 5. Risk levels are conservative and contextual

The `riskLevel` field in stage 1 is a **prioritization aid**, not a definitive classification.

In particular:

- `High` requires explicit linked service MI evidence.
- `Medium` reflects trusted bypass with partial or indirect supporting evidence.
- `Low` represents broad candidate discovery.

Downstream decisions should rely on the **stage‑2 confidence classification** combined with human review.

---

## 6. Connector coverage is not exhaustive

Only commonly observed Storage and Key Vault–related linked service types are explicitly recognized. New or uncommon connectors may:

- Appear as `targetKind = Unknown`
- Require manual interpretation
- Still be retained as Low confidence if scenario evidence exists

---

## 7. Cross‑subscription and cross‑tenant paths

The scripts assume:

- Visibility via Azure Resource Graph in the scanned subscriptions
- Inventory targets reside in accessible subscriptions

They do not:

- Traverse external tenants
- Validate trust boundaries
- Confirm effective permissions at runtime

---

## 8. Output is advisory, not compliance attestation

These scripts are intended to support:

- Discovery
- Triage
- Prioritization
- Manual review workflows

They should **not** be used as:

- Formal compliance attestations
- Automated enforcement mechanisms
- Proof of actual data exfiltration or runtime access
