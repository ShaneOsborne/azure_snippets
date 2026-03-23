# ManagedFirewallTrustedServices

Scripts to inventory Azure Data Factory linked services and identify cases where Trusted Microsoft Services bypass settings may still be effectively active for Storage or Key Vault targets.

## Files

- `Get-AdfTrustedBypassRiskReport.ps1`
  - Generates a full risk report CSV from Azure Resource Graph and ADF REST APIs.
  - Default output: `adf_risk_report_v3_pwsh.csv`

- `Get-AffectedServices.ps1`
  - Filters the full risk report to only rows considered affected.
  - Default output: `adf_risk_report_AFFECTED_ONLY.csv`

- `ADF_affected_services.sh`
  - Bash/Azure CLI implementation of the inventory workflow.
  - Output: `adf_risk_report_v3.csv`

## Prerequisites

### PowerShell scripts

- PowerShell 7+
- Az modules:
  - `Az.Accounts`
  - `Az.ResourceGraph`
- Access to the target subscriptions

Install if needed:

```powershell
Install-Module Az.Accounts -Scope CurrentUser
Install-Module Az.ResourceGraph -Scope CurrentUser
```

### Bash script

- Bash environment (Cloud Shell, WSL, Linux, macOS)
- Azure CLI (`az`) logged in
- `jq`

## Usage

### 1) Build full report (PowerShell)

```powershell
cd AzureDataFactory/ManagedFirewallTrustedServices
./Get-AdfTrustedBypassRiskReport.ps1
```

Optional single-subscription run:

```powershell
./Get-AdfTrustedBypassRiskReport.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"
```

Optional output path:

```powershell
./Get-AdfTrustedBypassRiskReport.ps1 -OutputPath "./adf_risk_report_custom.csv"
```

### 2) Filter to affected services (PowerShell)

```powershell
./Get-AffectedServices.ps1
```

Custom input and output:

```powershell
./Get-AffectedServices.ps1 -InputPath "./adf_risk_report_v3_pwsh.csv" -OutputPath "./adf_risk_report_AFFECTED_ONLY.csv"
```

### 3) Bash alternative

```bash
cd AzureDataFactory/ManagedFirewallTrustedServices
bash ADF_affected_services.sh <subscription-id>
```

If no subscription ID is provided, the script uses the currently selected Azure CLI account subscription.

## Notes

- Target URI extraction from linked services is best-effort.
- Parameterized linked services or connectors without explicit URI fields may not fully classify target type.
- Confirm findings against your environment and security requirements before remediation.
