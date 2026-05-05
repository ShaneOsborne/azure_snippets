# Guidance for Using the Scripts

These scripts are intended to support **discovery, prioritization, and manual review** for the Azure Data Factory managed identity + trusted services firewall bypass retirement scenario. They are designed as a two-stage workflow:

- **Stage 1** – `Get-AdfTrustedBypassRiskReport.ps1`: Produces a broad candidate report using metadata such as linked services, managed identity signals, integration runtime usage, target resolution, inventory matches, and firewall settings.

- **Stage 2** – `Get-AffectedServices.ps1`: Reduces the stage-1 output into a narrower list of likely affected or manual-review rows using confidence-based filtering.

The scripts are intentionally conservative. Their purpose is to **reduce blind spots and focus engineering effort**, not to provide definitive proof of runtime impact.

---

## How to Interpret the Results

These scripts are designed to support **discovery, prioritization, and manual review**, not to provide definitive proof of runtime impact.

### Stage 1 Output

`Get-AdfTrustedBypassRiskReport.ps1` produces a broad candidate list with conservative risk signals based on available metadata such as:

- Linked services
- Identities
- Firewall configuration
- Target resolution
- Inventory matches

Its purpose is to **surface areas where attention may be required, even when evidence is incomplete**.

### Stage 2 Output

`Get-AffectedServices.ps1` reduces this list into confidence-based outcomes:

#### High Confidence

Strong indicators that a linked service accesses Storage or Key Vault using managed identity with trusted services bypass effectively enabled. **These rows should be prioritized first.**

#### Medium Confidence

Trusted services bypass is effective and the target is relevant, but managed identity usage is missing, indirect, or inferred from contextual signals such as:

- Factory identity
- IR type
- Scenario context

**These rows warrant review to confirm actual runtime behavior.**

#### Low Confidence / Manual Review

Evidence is partial, indirect, or parameterized, but still suggests potential relevance. These rows are retained intentionally to **avoid false negatives** and should be reviewed selectively based on:

- Risk tolerance
- Business criticality
- Exposure level

### Key Validation Point

In all cases, **human validation is expected**. Parameterized targets, REST/Web/Azure Function scenarios, and unresolved endpoints typically require pipeline or activity inspection to determine actual runtime access patterns.

---

## How to Prioritize Reviews

Use the stage-2 confidence classification to **focus review effort where it matters most**, rather than treating all rows equally.

### Start with High Confidence Rows

These represent the strongest signals of potential impact:

- Relevant Storage or Key Vault target
- Trusted services bypass effectively enabled
- Explicit linked service managed identity usage

**These rows should be reviewed first and typically routed into remediation planning.**

### Review Medium Confidence Rows Next

Medium confidence rows indicate:

- Trusted services bypass is effective
- Target is relevant
- Managed identity usage is missing, indirect, or inferred from contextual signals

**Prioritize these where:**

- Environment is highly regulated
- Factory supports critical workloads
- Multiple Medium rows surface across the same factory or subscription

### Treat Low Confidence Rows as Selective Manual Review

Low confidence rows are retained intentionally to avoid false negatives. They typically involve:

- Parameterized targets
- REST/Web/Azure Function scenarios
- Self-Hosted or Azure-SSIS runtimes
- Incomplete target resolution

**These should be sampled or reviewed based on risk tolerance, exposure, and business criticality rather than exhaustively validated.**

### Use Reason Codes to Guide Effort

`filterReasonCodes` explain why a row was retained. Rows marked with:

- `NeedsPipelineInspection`
- `ParameterizedTarget`
- REST/Web/AzureFunction scenario signals

...usually require pipeline or activity inspection to confirm runtime behavior.

### Group by Factory and Subscription for Efficiency

When multiple rows surface under the same factory, **review them together**. Shared patterns across a factory are often more informative than inspecting rows one by one.

### Overall Strategy

The goal is to:

1. **Prioritize certainty first**
2. **Reduce blind spots second**
3. **Apply manual inspection where automation cannot safely infer runtime behavior**

---

## Remediation Next Steps

Use the confidence classification to guide remediation planning rather than applying the same response to every row.

### High Confidence Rows

Treat these as the most likely candidates for change.

**Typical next steps:**

1. Confirm the linked service, runtime, and target resource involved
2. Assess which supported access pattern should replace trusted services bypass
3. Validate whether the workload should move to:
   - IP allow-listing for Self-Hosted IR or Azure-SSIS outbound access
   - Managed virtual network with private endpoints
   - Customer-owned virtual network where Azure-SSIS integration is required

### Medium Confidence Rows

Validate actual runtime behavior before planning remediation.

**Review:**

1. Linked service configuration
2. Integration runtime path
3. Whether managed identity is truly used at execution time

Where uncertainty remains, inspect the relevant pipeline or activity definition.

### Low Confidence / Manual Review Rows

Use these as a review backlog rather than an immediate remediation queue.

**Focus on rows marked with signals such as:**

- `NeedsPipelineInspection`
- `ParameterizedTarget`
- REST/Web/AzureFunction scenarios
- Incomplete target resolution

### Validate Changes Safely

- Test changes first in non-production environments where possible
- Verify that access continues to work without relying on trusted services bypass
- Use any available validation toggle or staged rollout capability before production deployment

### Track by Factory, Not Just by Row

Multiple retained rows in the same factory often indicate a shared design pattern.

- Review them together
- Define remediation at the factory or workload level where possible

### Document Decisions and Exceptions

For each reviewed item, record whether it is:

- Confirmed affected
- Not affected after validation
- Already remediated
- Pending architectural change

This helps distinguish genuine risk from discovery noise over time.

---

## Recommended Workflow

A practical review and remediation workflow is:

### 1. Run Stage 1

Execute `Get-AdfTrustedBypassRiskReport.ps1` to generate the broad candidate report.

```powershell
./Get-AdfTrustedBypassRiskReport.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"
```

### 2. Run Stage 2

Execute `Get-AffectedServices.ps1` against the stage-1 CSV to reduce the output into High, Medium, and Low confidence rows.

```powershell
./Get-AffectedServices.ps1
```

### 3. Prioritize High Confidence Rows First

Review and triage the strongest candidates for remediation planning.

### 4. Review Medium Confidence Rows

Validate actual runtime behavior, especially where MI usage is inferred or indirect.

### 5. Sample or Selectively Inspect Low Confidence Rows

Focus on rows with `NeedsPipelineInspection`, `ParameterizedTarget`, REST/Web/AzureFunction patterns, or incomplete target resolution.

### 6. Inspect Pipelines or Activities Where Needed

For unresolved or parameterized cases, check the actual pipeline/activity definitions to confirm runtime target and authentication behavior.

### 7. Define Remediation by Factory/Workload Pattern

Where multiple rows indicate the same architectural dependency, plan remediation at the workload or factory level rather than row-by-row.

### 8. Test and Validate Before Rollout

Confirm that access works correctly without trusted services bypass, ideally in test or non-production environments first.

### 9. Record Outcomes

Track whether each reviewed item is:

- Confirmed affected
- Not affected
- Remediated
- Pending change

This makes future reviews faster and more consistent.

---

## See Also

- [README.md](./README.md) – Overview, usage instructions, and prerequisites
- [LIMITATIONS.md](./LIMITATIONS.md) – Detailed known limitations and design trade-offs
