<#
.SYNOPSIS
  Reduces an ADF trusted bypass risk report CSV to likely affected or manual-review rows.

.DESCRIPTION
  Reads the output CSV produced by Get-AdfTrustedBypassRiskReport.ps1 and keeps a narrower,
  more actionable subset for the ADF managed identity + trusted services firewall bypass
  retirement scenario.

  This is a stage-2 reducer over the stage-1 report. It does not query Azure directly and does
  not inspect pipelines or activities. Rows are classified as High, Medium, or Low confidence
  rather than treated as definitive proof of impact.

  Core keep logic:
    - The target must be Storage or KeyVault.
    - trustedBypassEffective = Y is the strongest bypass signal.
    - trustedBypassConfigured = Y can keep lower-confidence manual-review rows when other
      evidence is relevant.
    - usesManagedIdentity = Y is strong linked service MI evidence.
    - factoryHasSystemAssignedMI = Y is stronger factory MI evidence than user-assigned MI.
    - SelfHosted, AzureSSIS, REST, Web, and AzureFunction-style linked service signals can
      retain rows where MI evidence is incomplete.

  affectedConfidence values:
    - High: Storage/KeyVault target + trusted bypass effective + linked service MI evidence
      plus at least one strong factory/IR/scenario signal.
    - Medium: Storage/KeyVault target + trusted bypass effective, but linked service MI
      evidence is missing, negative, or uncertain while other relevance signals remain.
    - Low: Storage/KeyVault target with trusted bypass configured/effective and enough
      scenario or identity evidence to warrant manual review, but not enough for Medium.

  filterReasonCodes explains why a row was retained, for example:
    TrustedBypassEffective;UsesManagedIdentity;FactoryHasSystemAssignedMI;UsesSHIR;
    UsesAzureSSIS;RESTScenario;WebLikeScenario;AzureFunctionLikeScenario;
    MissingMIEvidenceButScenarioRelevant;NeedsManualReview

  User-assigned managed identity is treated as weaker evidence than system-assigned managed
  identity for this scenario. User-assigned MI alone lowers confidence unless other scenario
  signals justify keeping the row.

  Results are exported to a CSV and displayed as a formatted table.
  A separate explanation CSV is also written so excluded rows have a user-friendly reason.
  Use -HideExplanations to suppress the console explanation table when no affected rows are found.

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

.EXAMPLE
  .\Get-AffectedServices.ps1 -HideExplanations
  Writes the affected and explanation CSV files without printing the no-match explanation table.
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

function Get-RowValue {
  param(
    [Parameter(Mandatory=$true)]$Row,
    [Parameter(Mandatory=$true)][string]$Name,
    [string]$Default = ""
  )

  # Be tolerant of older stage-1 CSVs. Missing columns should reduce confidence,
  # not make the reducer fail before a human can review the evidence.
  $prop = $Row.PSObject.Properties[$Name]
  if (-not $prop -or $null -eq $prop.Value) { return $Default }
  return [string]$prop.Value
}

function Test-Yes {
  param([string]$Value)
  return $Value -eq "Y"
}

function Get-AffectedEvaluation {
  param([Parameter(Mandatory=$true)]$Row)

  $targetKind = Get-RowValue -Row $Row -Name "targetKind"
  $trustedConfigured = Get-RowValue -Row $Row -Name "trustedBypassConfigured"
  $trustedEffective = Get-RowValue -Row $Row -Name "trustedBypassEffective"
  $usesManagedIdentity = Get-RowValue -Row $Row -Name "usesManagedIdentity" -Default "?"
  $factoryHasSystemAssignedMI = Get-RowValue -Row $Row -Name "factoryHasSystemAssignedMI" -Default "?"
  $factoryHasUserAssignedMI = Get-RowValue -Row $Row -Name "factoryHasUserAssignedMI" -Default "?"
  $connectViaIRClass = Get-RowValue -Row $Row -Name "connectViaIRClass"
  $linkedServiceType = Get-RowValue -Row $Row -Name "linkedServiceType"
  $scenarioCategory = Get-RowValue -Row $Row -Name "scenarioCategory"
  $targetDetectionStatus = Get-RowValue -Row $Row -Name "targetDetectionStatus"
  $stage1RiskLevel = Get-RowValue -Row $Row -Name "riskLevel"

  $targetIsStorageOrKeyVault = $targetKind -eq "Storage" -or $targetKind -eq "KeyVault"
  $trustedBypassIsEffective = Test-Yes -Value $trustedEffective
  $trustedBypassIsConfigured = Test-Yes -Value $trustedConfigured
  $lsUsesManagedIdentity = Test-Yes -Value $usesManagedIdentity
  $factoryHasSystemAssigned = Test-Yes -Value $factoryHasSystemAssignedMI
  $factoryHasUserAssigned = Test-Yes -Value $factoryHasUserAssignedMI

  $usesSHIR = $connectViaIRClass -eq "SelfHosted" -or $scenarioCategory -match '(^|;)SHIR'
  $usesAzureSSIS = $connectViaIRClass -eq "AzureSSIS" -or $scenarioCategory -match '(^|;)AzureSSIS'
  $restScenario = $linkedServiceType -eq "RestService" -or $scenarioCategory -match 'REST_LinkedService'
  $webLikeScenario = $linkedServiceType -eq "Web" -or $scenarioCategory -match 'Web_(LinkedServiceEvidence|ActivityOrLS)'
  $azureFunctionLikeScenario = $linkedServiceType -eq "AzureFunction" -or $scenarioCategory -match 'AzureFunction_(LinkedServiceEvidence|ActivityOrLS)'
  $storageOrKvConnector = $linkedServiceType -match '^(AzureBlobFS|AzureBlobStorage|AzureTableStorage|AzureQueueStorage|AzureFileStorage|AzureKeyVault)$'
  $scenarioRelevant = $usesSHIR -or $usesAzureSSIS -or $restScenario -or $webLikeScenario -or $azureFunctionLikeScenario -or $storageOrKvConnector

  $reasonCodes = New-Object System.Collections.Generic.List[string]
  $excludeReasons = New-Object System.Collections.Generic.List[string]

  if ($targetIsStorageOrKeyVault) { $reasonCodes.Add("TargetIsStorageOrKeyVault") | Out-Null }
  if ($trustedBypassIsEffective) { $reasonCodes.Add("TrustedBypassEffective") | Out-Null }
  elseif ($trustedBypassIsConfigured) { $reasonCodes.Add("TrustedBypassConfigured") | Out-Null }
  if ($lsUsesManagedIdentity) { $reasonCodes.Add("UsesManagedIdentity") | Out-Null }
  if ($factoryHasSystemAssigned) { $reasonCodes.Add("FactoryHasSystemAssignedMI") | Out-Null }
  if ($factoryHasUserAssigned) { $reasonCodes.Add("FactoryHasUserAssignedMI") | Out-Null }
  if ($usesSHIR) { $reasonCodes.Add("UsesSHIR") | Out-Null }
  if ($usesAzureSSIS) { $reasonCodes.Add("UsesAzureSSIS") | Out-Null }
  if ($restScenario) { $reasonCodes.Add("RESTScenario") | Out-Null }
  if ($webLikeScenario) { $reasonCodes.Add("WebLikeScenario") | Out-Null }
  if ($azureFunctionLikeScenario) { $reasonCodes.Add("AzureFunctionLikeScenario") | Out-Null }
  if ($storageOrKvConnector) { $reasonCodes.Add("StorageOrKeyVaultConnector") | Out-Null }
  if ($targetDetectionStatus -eq "Parameterized") { $reasonCodes.Add("ParameterizedTarget") | Out-Null }

  if (-not $targetIsStorageOrKeyVault) {
    $excludeReasons.Add("Excluded because targetKind is '$targetKind', not Storage or KeyVault.") | Out-Null
  }

  if (-not $trustedBypassIsEffective -and -not $trustedBypassIsConfigured) {
    $excludeReasons.Add("Excluded because trusted bypass is neither effective nor configured in the stage-1 report.") | Out-Null
  }

  if (-not $scenarioRelevant -and -not $lsUsesManagedIdentity -and -not $factoryHasSystemAssigned -and $stage1RiskLevel -ne "High") {
    $excludeReasons.Add("Excluded because MI/scenario evidence is too weak for the stage-2 reducer.") | Out-Null
  }

  $confidence = ""
  $included = $false

  $strongScenarioOrFactorySignal =
    $factoryHasSystemAssigned -or
    $usesSHIR -or
    $usesAzureSSIS -or
    $restScenario -or
    $webLikeScenario -or
    $azureFunctionLikeScenario

  if ($targetIsStorageOrKeyVault -and $trustedBypassIsEffective -and $lsUsesManagedIdentity -and $strongScenarioOrFactorySignal) {
    $included = $true
    $confidence = "High"
  }
  elseif ($targetIsStorageOrKeyVault -and $trustedBypassIsEffective -and ($scenarioRelevant -or $factoryHasSystemAssigned -or $stage1RiskLevel -eq "High")) {
    $included = $true
    $confidence = "Medium"
    if (-not $lsUsesManagedIdentity) {
      $reasonCodes.Add("MissingMIEvidenceButScenarioRelevant") | Out-Null
    }
    if ($factoryHasUserAssigned -and -not $factoryHasSystemAssigned) {
      $reasonCodes.Add("UserAssignedMINotStrongEvidence") | Out-Null
    }
  }
  elseif ($targetIsStorageOrKeyVault -and ($trustedBypassIsEffective -or $trustedBypassIsConfigured) -and ($scenarioRelevant -or $lsUsesManagedIdentity -or $factoryHasSystemAssigned -or $factoryHasUserAssigned)) {
    $included = $true
    $confidence = "Low"
    $reasonCodes.Add("NeedsManualReview") | Out-Null
    if (-not $lsUsesManagedIdentity) {
      $reasonCodes.Add("MissingMIEvidenceButScenarioRelevant") | Out-Null
    }
    if ($factoryHasUserAssigned -and -not $factoryHasSystemAssigned) {
      $reasonCodes.Add("UserAssignedMINotStrongEvidence") | Out-Null
    }
  }

  $reasonText = if ($included) {
    "Included as $confidence confidence for likely affected/manual review filtering."
  } elseif ($excludeReasons.Count -gt 0) {
    ($excludeReasons -join " ")
  } else {
    "Excluded because the row did not meet the stage-2 likely affected criteria."
  }

  return [pscustomobject]@{
    Included          = if ($included) { "Y" } else { "N" }
    Confidence        = $confidence
    FilterReasonCodes = ($reasonCodes | Select-Object -Unique) -join ';'
    Reason            = $reasonText
  }
}

$explanation = @(foreach ($row in $csv) {
  $evaluation = Get-AffectedEvaluation -Row $row

  [pscustomobject]@{
    included                  = $evaluation.Included
    affectedConfidence        = $evaluation.Confidence
    filterReasonCodes         = $evaluation.FilterReasonCodes
    reason                    = $evaluation.Reason
    subscriptionId            = $row.subscriptionId
    resourceGroup             = $row.resourceGroup
    factoryName               = $row.factoryName
    factoryIdentityType       = $row.factoryIdentityType
    factoryHasSystemAssignedMI = $row.factoryHasSystemAssignedMI
    factoryHasUserAssignedMI  = $row.factoryHasUserAssignedMI
    linkedServiceName         = $row.linkedServiceName
    linkedServiceType         = $row.linkedServiceType
    usesManagedIdentity       = $row.usesManagedIdentity
    connectViaIR              = $row.connectViaIR
    connectViaIRClass         = $row.connectViaIRClass
    scenarioCategory          = $row.scenarioCategory
    targetUri                 = $row.targetUri
    targetDetectionStatus     = $row.targetDetectionStatus
    targetKind                = $row.targetKind
    targetName                = $row.targetName
    trustedBypassConfigured   = $row.trustedBypassConfigured
    trustedBypassEffective    = $row.trustedBypassEffective
    riskLevel                 = $row.riskLevel
    reasonCodes               = $row.reasonCodes
    targetPna                 = $row.targetPna
    targetDefaultAction       = $row.targetDefaultAction
    targetBypass              = $row.targetBypass
  }
})

$affected = @(foreach ($row in $csv) {
  $evaluation = Get-AffectedEvaluation -Row $row
  if ($evaluation.Included -eq "Y") {
    [pscustomobject]@{
      affectedConfidence        = $evaluation.Confidence
      filterReasonCodes         = $evaluation.FilterReasonCodes
      subscriptionId            = $row.subscriptionId
      resourceGroup             = $row.resourceGroup
      factoryName               = $row.factoryName
      factoryIdentityType       = $row.factoryIdentityType
      factoryHasSystemAssignedMI = $row.factoryHasSystemAssignedMI
      factoryHasUserAssignedMI  = $row.factoryHasUserAssignedMI
      linkedServiceName         = $row.linkedServiceName
      linkedServiceType         = $row.linkedServiceType
      authType                  = $row.authType
      usesManagedIdentity       = $row.usesManagedIdentity
      connectViaIR              = $row.connectViaIR
      connectViaIRClass         = $row.connectViaIRClass
      scenarioCategory          = $row.scenarioCategory
      targetUri                 = $row.targetUri
      targetDetectionStatus     = $row.targetDetectionStatus
      targetKind                = $row.targetKind
      targetName                = $row.targetName
      targetPna                 = $row.targetPna
      targetDefaultAction       = $row.targetDefaultAction
      targetBypass              = $row.targetBypass
      trustedBypassConfigured   = $row.trustedBypassConfigured
      trustedBypassEffective    = $row.trustedBypassEffective
      riskLevel                 = $row.riskLevel
      reasonCodes               = $row.reasonCodes
      integrationRuntimesAll    = $row.integrationRuntimesAll
    }
  }
})

try {
  $affected | Export-Csv $OutputPath -NoTypeInformation
  $explanation | Export-Csv $ExplanationPath -NoTypeInformation
}
catch {
  throw "Could not write the output CSV. Close the file if it is open in Excel/VS Code and check write permissions. Original error: $($_.Exception.Message)"
}

Write-Host "Done. Wrote $($affected.Count) likely affected / manual-review rows to: $OutputPath"
Write-Host "Wrote filter explanation for $($explanation.Count) input rows to: $ExplanationPath"

if (-not $HideExplanations -and $affected.Count -eq 0 -and $explanation.Count -gt 0) {
  Write-Host ""
  Write-Host "Why no rows were written:"
  $explanation |
    Sort-Object subscriptionId, resourceGroup, factoryName, linkedServiceName |
    Select-Object linkedServiceName, linkedServiceType, scenarioCategory, trustedBypassEffective, reason |
    Format-Table -Wrap -AutoSize
}

$affected |
  Sort-Object affectedConfidence, subscriptionId, resourceGroup, factoryName |
  Select-Object affectedConfidence, linkedServiceName, linkedServiceType, targetKind, trustedBypassEffective, usesManagedIdentity, filterReasonCodes |
  Format-Table -Wrap -AutoSize
