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

.PARAMETER ExplanationPath
  Optional path for a CSV explaining why each input row was included or excluded.
  Defaults to .\adf_risk_report_FILTER_EXPLANATION.csv

.PARAMETER HideExplanations
  Suppresses the console explanation table when no affected rows are found.

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
  [string]$OutputPath = ".\adf_risk_report_AFFECTED_ONLY.csv",

  [Parameter(Mandatory = $false)]
  [string]$ExplanationPath = ".\adf_risk_report_FILTER_EXPLANATION.csv",

  [Parameter(Mandatory = $false)]
  [switch]$HideExplanations
)

$ErrorActionPreference = "Stop"

$csv = Import-Csv $InputPath
$riskyScenarioPattern = 'SHIR|AzureSSIS|REST_LinkedService|Web_ActivityOrLS|AzureFunction_ActivityOrLS'

$explanation = foreach ($row in $csv) {
  $trustedEffective = $row.trustedBypassEffective -eq 'Y'
  $riskyScenario = $row.scenarioCategory -match $riskyScenarioPattern

  $reasons = New-Object System.Collections.Generic.List[string]

  if (-not $trustedEffective) {
    if ($row.trustedBypassEffective -eq '?') {
      $reasons.Add("Trusted bypass effectiveness is unknown because the linked service target could not be matched to a Storage account or Key Vault in the report.") | Out-Null
    } else {
      $reasons.Add("Trusted bypass is not effectively active. Expected trustedBypassEffective = Y, found '$($row.trustedBypassEffective)'.") | Out-Null
    }
  }

  if (-not $riskyScenario) {
    $reasons.Add("Scenario '$($row.scenarioCategory)' is not one of the advisory scenario types filtered as affected: SHIR, AzureSSIS, REST, Web, or AzureFunction.") | Out-Null
  }

  if ($trustedEffective -and $riskyScenario) {
    $reasons.Add("Included because trusted bypass is effectively active and the scenario matches an affected advisory type.") | Out-Null
  }

  [pscustomobject]@{
    included                  = if ($trustedEffective -and $riskyScenario) { "Y" } else { "N" }
    reason                    = ($reasons -join " ")
    subscriptionId            = $row.subscriptionId
    resourceGroup             = $row.resourceGroup
    factoryName               = $row.factoryName
    linkedServiceName         = $row.linkedServiceName
    linkedServiceType         = $row.linkedServiceType
    scenarioCategory          = $row.scenarioCategory
    targetKind                = $row.targetKind
    targetName                = $row.targetName
    trustedBypassConfigured   = $row.trustedBypassConfigured
    trustedBypassEffective    = $row.trustedBypassEffective
    targetPna                 = $row.targetPna
    targetDefaultAction       = $row.targetDefaultAction
    targetBypass              = $row.targetBypass
  }
}

$affected = $csv | Where-Object {
  $_.trustedBypassEffective -eq 'Y' -and
  ($_.scenarioCategory -match $riskyScenarioPattern)
}

try {
  $affected | Export-Csv $OutputPath -NoTypeInformation
  $explanation | Export-Csv $ExplanationPath -NoTypeInformation
}
catch {
  throw "Could not write the output CSV. Close the file if it is open in Excel/VS Code and check write permissions. Original error: $($_.Exception.Message)"
}

Write-Host "Done. Wrote $($affected.Count) affected rows to: $OutputPath"
Write-Host "Wrote filter explanation for $($explanation.Count) input rows to: $ExplanationPath"

if (-not $HideExplanations -and $affected.Count -eq 0 -and $explanation.Count -gt 0) {
  Write-Host ""
  Write-Host "Why no rows were written:"
  $explanation |
    Sort-Object subscriptionId, resourceGroup, factoryName, linkedServiceName |
    Select-Object linkedServiceName, linkedServiceType, scenarioCategory, trustedBypassEffective, reason |
    Format-Table -Wrap -AutoSize
}

$affected | Sort-Object subscriptionId, resourceGroup, factoryName | Format-Table -AutoSize
