# ManagedFirewallTrustedServices

Scripts to inventory Azure Data Factory linked services and identify candidate impact for the Azure Data Factory managed identity + Trusted Microsoft Services firewall bypass retirement scenario.

This is a two-stage workflow:

- Stage 1, `Get-AdfTrustedBypassRiskReport.ps1`, builds a broad discovery/risk report.
- Stage 2, `Get-AffectedServices.ps1`, reduces the broad report into a narrower likely affected/manual-review set.

These scripts are designed to support investigation. They do not prove final impact because pipeline/activity inspection and connector-specific runtime behavior may still need validation.

## Files

- `Get-AdfTrustedBypassRiskReport.ps1`
  - Generates a broad risk report CSV from Azure Resource Graph and ADF REST APIs.
  - Defaults to Azure CLI authentication, so it uses the account from `az login`.
  - Default output: `adf_risk_report_v3_pwsh.csv`

- `Get-AffectedServices.ps1`
  - Filters the full risk report to likely affected or manual-review rows.
  - Default output: `adf_risk_report_AFFECTED_ONLY.csv`
  - Also writes a row-by-row filter explanation CSV by default.
  - Default explanation output: `adf_risk_report_FILTER_EXPLANATION.csv`

## Stage 1 Risk Report Logic

`Get-AdfTrustedBypassRiskReport.ps1` inventories:

- Storage accounts:
  `networkAcls.bypass`, `networkAcls.defaultAction`, `publicNetworkAccess`
- Key Vaults:
  `networkAcls.bypass`, `networkAcls.defaultAction`, `publicNetworkAccess`
- Data Factories:
  identity type and user-assigned identity presence
- ADF linked services and integration runtimes through ADF REST APIs

The report correlates linked service target fields such as `url`, `baseUrl`, and `serviceEndpoint` to Storage or Key Vault resources when they are directly available. Parameterized linked services are flagged rather than resolved.

Important output fields include:

- `factoryIdentityType`
- `factoryHasSystemAssignedMI`
- `factoryHasUserAssignedMI`
- `usesManagedIdentity`
- `connectViaIRClass`
- `targetDetectionStatus`
- `targetKind`
- `trustedBypassConfigured`
- `trustedBypassEffective`
- `riskLevel`
- `reasonCodes`

Stage 1 `riskLevel` is deliberately conservative:

- `High`: Storage/KeyVault target + trusted bypass effective + managed identity evidence.
- `Medium`: Storage/KeyVault target + trusted bypass effective, but MI evidence is incomplete.
- `Low`: broader candidate signal or incomplete evidence.

`trustedBypassEffective = Y` means the target resource was matched and the report saw:

- bypass includes `AzureServices`
- public network access is not disabled
- default network action is `Deny`

`targetDetectionStatus` helps explain target URI quality:

- `Direct`: a URL-like field was found directly in the linked service.
- `Parameterized`: the target appears expression-based or parameterized.
- `NotFound`: no supported target URI field was found.
- `Unknown`: type properties were not available.

## Stage 2 Filtering Logic

`Get-AffectedServices.ps1` is a reducer over the Stage 1 CSV. It does not query Azure, inspect pipelines, or inspect activities.

The reducer keeps rows when they have enough evidence for likely impact or manual review. The main signals are:

- target is `Storage` or `KeyVault`
- `trustedBypassEffective = Y`
- `usesManagedIdentity = Y`
- `factoryHasSystemAssignedMI = Y`
- `connectViaIRClass` is `SelfHosted` or `AzureSSIS`
- `linkedServiceType` is REST/Web/AzureFunction-like
- Storage/Key Vault connector types where MI evidence is incomplete but bypass evidence is strong

User-assigned managed identity is treated as weaker evidence than system-assigned managed identity for this scenario. If `factoryHasUserAssignedMI = Y` but system-assigned evidence is absent, the row can still be retained, but confidence is lowered unless other scenario signals justify it.

### affectedConfidence

The affected-only output includes `affectedConfidence`:

- `High`: Storage/KeyVault target + trusted bypass effective + linked service MI evidence, plus at least one strong factory/IR/scenario signal.
- `Medium`: Storage/KeyVault target + trusted bypass effective, but linked service MI evidence is missing, negative, or uncertain while other relevance signals remain.
- `Low`: Storage/KeyVault target with trusted bypass configured/effective and enough scenario or identity evidence to warrant manual review, but not enough for Medium.

The output also includes `filterReasonCodes`, a semicolon-separated explanation for why the row was retained. Common codes include:

- `TrustedBypassEffective`
- `TrustedBypassConfigured`
- `UsesManagedIdentity`
- `FactoryHasSystemAssignedMI`
- `FactoryHasUserAssignedMI`
- `UsesSHIR`
- `UsesAzureSSIS`
- `RESTScenario`
- `WebLikeScenario`
- `AzureFunctionLikeScenario`
- `StorageOrKeyVaultConnector`
- `MissingMIEvidenceButScenarioRelevant`
- `UserAssignedMINotStrongEvidence`
- `NeedsManualReview`

## Prerequisites

- PowerShell 7+
- Azure CLI (`az`) logged in
- Access to the target subscriptions

Log in with Azure CLI:

```powershell
az login --use-device-code
az account set --subscription "<subscription-id>"
```

`Get-AdfTrustedBypassRiskReport.ps1` defaults to `-AuthMode AzureCli`. This intentionally uses Azure CLI's login cache, not Az PowerShell context.

Optional Az PowerShell compatibility mode requires:

- `Az.Accounts`
- `Az.ResourceGraph`

Install those only if you plan to run with `-AuthMode AzPowerShell`:

```powershell
Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser -Repository PSGallery -AllowClobber
```

## Usage

### 1) Build Full Report

```powershell
cd AzureDataFactory/ManagedFirewallTrustedServices
az login --use-device-code
az account set --subscription "00000000-0000-0000-0000-000000000000"
./Get-AdfTrustedBypassRiskReport.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"
```

The PowerShell report script uses Azure CLI auth by default. It prints the Azure CLI account, tenant, and subscription before scanning.

Optional tenant check:

```powershell
./Get-AdfTrustedBypassRiskReport.ps1 `
  -SubscriptionId "00000000-0000-0000-0000-000000000000" `
  -TenantId "11111111-1111-1111-1111-111111111111"
```

Optional output path:

```powershell
./Get-AdfTrustedBypassRiskReport.ps1 -OutputPath "./adf_risk_report_custom.csv"
```

Optional Az PowerShell mode:

```powershell
./Get-AdfTrustedBypassRiskReport.ps1 `
  -SubscriptionId "00000000-0000-0000-0000-000000000000" `
  -TenantId "11111111-1111-1111-1111-111111111111" `
  -AuthMode AzPowerShell
```

To pin Az PowerShell mode to a specific account:

```powershell
./Get-AdfTrustedBypassRiskReport.ps1 `
  -SubscriptionId "00000000-0000-0000-0000-000000000000" `
  -TenantId "11111111-1111-1111-1111-111111111111" `
  -AccountId "user@contoso.com" `
  -AuthMode AzPowerShell
```

### 2) Filter To Likely Affected / Manual Review Rows

```powershell
./Get-AffectedServices.ps1
```

This writes:

- `adf_risk_report_AFFECTED_ONLY.csv`
- `adf_risk_report_FILTER_EXPLANATION.csv`

The affected-only filter is now confidence-based. It prioritizes Storage/KeyVault targets where trusted bypass is effective and managed identity or scenario evidence is present. Rows with incomplete MI evidence can still be retained as Medium or Low confidence for manual validation.

If no affected rows are found, the script prints a friendly table explaining why each input row was excluded. To hide that console table:

```powershell
./Get-AffectedServices.ps1 -HideExplanations
```

Custom input and output:

```powershell
./Get-AffectedServices.ps1 -InputPath "./adf_risk_report_v3_pwsh.csv" -OutputPath "./adf_risk_report_AFFECTED_ONLY.csv"
```

Custom explanation output:

```powershell
./Get-AffectedServices.ps1 -ExplanationPath "./filter_explanation.csv"
```

## Notes

- Target URI extraction from linked services is best-effort.
- Parameterized linked services or connectors without explicit URI fields may not fully classify target type.
- Azure CLI and Az PowerShell maintain separate login/context caches. The default PowerShell report mode uses Azure CLI context.
- If a CSV cannot be overwritten, close it in Excel, VS Code, or any other app that may have locked the file.
- Confirm findings against your environment and security requirements before remediation.

## Guidance and Documentation

- [GUIDANCE.md](./GUIDANCE.md) – Comprehensive guidance on interpreting results, prioritizing reviews, remediation workflows, and best practices
- [LIMITATIONS.md](./LIMITATIONS.md) – Detailed discussion of known limitations, design trade-offs, and scope constraints
