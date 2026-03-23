<#
.SYNOPSIS
  Filters an ADF risk report CSV to rows where Trusted Bypass is effectively active and a risky scenario category applies.

.DESCRIPTION
  Reads the output CSV produced by Get-AdfTrustedBypassRiskReport.ps1 and filters it to only the
  linked services that are considered affected by the ADF Trusted Bypass advisory:
    - trustedBypassEffective = 'Y'  (bypass is configured, public network access not disabled, and defaultAction is Deny)
    - scenarioCategory matches one of: SHIR, AzureSSIS, REST_LinkedService, Web_ActivityOrLS, AzureFunction_ActivityOrLS

  Results are exported to a CSV and displayed as a formatted table.

.PARAMETER InputPath
  Path to the source risk report CSV (output of Get-AdfTrustedBypassRiskReport.ps1).
  Defaults to .\adf_risk_report_v3_pwsh.csv

.PARAMETER OutputPath
  Path for the filtered output CSV.
  Defaults to .\adf_risk_report_AFFECTED_ONLY.csv

.EXAMPLE
  .\Get-AffectedServices.ps1
  Reads .\adf_risk_report_v3_pwsh.csv and writes .\adf_risk_report_AFFECTED_ONLY.csv

.EXAMPLE
  .\Get-AffectedServices.ps1 -InputPath "C:\temp\MCAPS.csv" -OutputPath "C:\temp\affected.csv"
#>

param(
  [Parameter(Mandatory = $false)]
  [string]$InputPath = ".\adf_risk_report_v3_pwsh.csv",

  [Parameter(Mandatory = $false)]
  [string]$OutputPath = ".\adf_risk_report_AFFECTED_ONLY.csv"
)

$csv = Import-Csv $InputPath

$affected = $csv | Where-Object {
  $_.trustedBypassEffective -eq 'Y' -and
  ($_.scenarioCategory -match 'SHIR|AzureSSIS|REST_LinkedService|Web_ActivityOrLS|AzureFunction_ActivityOrLS')
}

$affected | Export-Csv $OutputPath -NoTypeInformation
Write-Host "Done. Wrote $($affected.Count) affected rows to: $OutputPath"
$affected | Sort-Object subscriptionId, resourceGroup, factoryName | Format-Table -AutoSize