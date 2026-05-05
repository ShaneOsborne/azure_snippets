# ManagedFirewallTrustedServices

Scripts to inventory Azure Data Factory linked services and identify cases where Trusted Microsoft Services bypass settings may still be effectively active for Storage or Key Vault targets.

## Files

- `Get-AdfTrustedBypassRiskReport.ps1`
  - Generates a full risk report CSV from Azure Resource Graph and ADF REST APIs.
  - Defaults to Azure CLI authentication, so it uses the account from `az login`.
  - Default output: `adf_risk_report_v3_pwsh.csv`

- `Get-AffectedServices.ps1`
  - Filters the full risk report to only rows considered affected.
  - Default output: `adf_risk_report_AFFECTED_ONLY.csv`
  - Also writes a row-by-row filter explanation CSV by default.
  - Default explanation output: `adf_risk_report_FILTER_EXPLANATION.csv`

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

### 2) Filter To Affected Services

```powershell
./Get-AffectedServices.ps1
```

This writes:

- `adf_risk_report_AFFECTED_ONLY.csv`
- `adf_risk_report_FILTER_EXPLANATION.csv`

The affected-only filter requires both:

- `trustedBypassEffective = Y`
- `scenarioCategory` matches one of `SHIR`, `AzureSSIS`, `REST_LinkedService`, `Web_ActivityOrLS`, or `AzureFunction_ActivityOrLS`

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
