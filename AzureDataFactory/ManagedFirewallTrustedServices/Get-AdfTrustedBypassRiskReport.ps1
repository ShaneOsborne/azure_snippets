<#
.SYNOPSIS
  Produces an ADF security advisory risk report across one subscription or all accessible subscriptions.

.DESCRIPTION
  - Uses Azure Resource Graph (Search-AzGraph) to inventory:
      * Storage accounts: networkAcls.bypass, networkAcls.defaultAction, publicNetworkAccess
      * Key Vaults:      networkAcls.bypass, networkAcls.defaultAction, publicNetworkAccess
      * Data Factories
    (Search-AzGraph supports subscription scope or tenant scope and includes paging support via SkipToken) [1](https://learn.microsoft.com/en-us/powershell/module/az.resourcegraph/search-azgraph?view=azps-15.4.0)[2](https://learn.microsoft.com/en-us/azure/governance/resource-graph/first-query-powershell)

  - Uses Azure Data Factory REST APIs:
      * Linked Services - List By Factory (api-version 2018-06-01) 
      * Integration Runtimes - List By Factory (api-version 2018-06-01) [3](https://learn.microsoft.com/en-us/rest/api/datafactory/integration-runtimes/list-by-factory?view=rest-datafactory-2018-06-01)

.PARAMETER SubscriptionId
  Optional. If supplied, scans only that subscription. Otherwise scans all accessible subscriptions.

.PARAMETER OutputPath
  Output CSV path.

.EXAMPLE
  .\Get-AdfTrustedBypassRiskReport.ps1
  Scans all subscriptions you can access and writes .\adf_risk_report_v3_pwsh.csv

.EXAMPLE
  .\Get-AdfTrustedBypassRiskReport.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -OutputPath "C:\temp\adf.csv"
#>

param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$OutputPath = ".\adf_risk_report_v3_pwsh.csv"
)

$ErrorActionPreference = "Stop"
$ApiVersion = "2018-06-01"

# ----------------------------
# Helpers
# ----------------------------

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    throw "Required module '$Name' not found. Install it e.g. Install-Module $Name -Scope CurrentUser"
  }
}

function Get-AllAzGraph {
  <#
    Executes a Search-AzGraph query across provided subscriptions, handling paging via SkipToken.
    Search-AzGraph supports -Subscription and -SkipToken for pagination. [1](https://learn.microsoft.com/en-us/powershell/module/az.resourcegraph/search-azgraph?view=azps-15.4.0)
  #>
  param(
    [Parameter(Mandatory=$true)][string]$Query,
    [Parameter(Mandatory=$false)][string[]]$Subscriptions
  )

  $results = @()
  $skipToken = $null

  do {
    if ($Subscriptions -and $Subscriptions.Count -gt 0) {
      $resp = Search-AzGraph -Query $Query -Subscription $Subscriptions -First 1000 -SkipToken $skipToken
    } else {
      # tenant-scope (if allowed) – may require additional permissions
      $resp = Search-AzGraph -Query $Query -UseTenantScope -AllowPartialScope -First 1000 -SkipToken $skipToken
    }

    if ($resp.Data) { $results += $resp.Data }
    $skipToken = $resp.SkipToken
  } while ($skipToken)

  return $results
}

function Parse-HostFromUri {
  param([string]$Uri)
  if ([string]::IsNullOrWhiteSpace($Uri)) { return "" }
  $u = $Uri -replace '^https?://',''
  return ($u.Split('/')[0])
}

function Classify-TargetKind {
  param([string]$Hostname)
  if ($Hostname -match '\.vault\.') { return "KeyVault" }
  if ($Hostname -match '\.(blob|dfs|queue|table)\.') { return "Storage" }
  return "Unknown"
}

function Normalize-Pna {
  param([string]$PublicNetworkAccess)
  if ([string]::IsNullOrWhiteSpace($PublicNetworkAccess)) { return "Enabled(implicit)" }
  return $PublicNetworkAccess
}

function Get-IrClass {
  param($IrProps)
  # IR REST schema returns .properties.type and (for Azure-SSIS) .properties.typeProperties.ssisProperties.
  if ($IrProps.type -eq "SelfHosted") { return "SelfHosted" }
  if ($null -ne $IrProps.typeProperties -and $null -ne $IrProps.typeProperties.ssisProperties) { return "AzureSSIS" }
  return "AzureIR"
}

function Build-ScenarioCategory {
  param(
    [string]$LinkedServiceType,
    [string]$IrClass,
    [string]$TargetKind
  )

  $suffix = ""
  if ($TargetKind -eq "Storage") { $suffix = "_toStorage" }
  elseif ($TargetKind -eq "KeyVault") { $suffix = "_toKeyVault" }

  $cats = New-Object System.Collections.Generic.List[string]

  # Connector-driven categories (match the Microsoft advisory wording)
  if ($LinkedServiceType -eq "RestService")    { $cats.Add("REST_LinkedService$suffix") | Out-Null }
  if ($LinkedServiceType -eq "Web")           { $cats.Add("Web_ActivityOrLS$suffix") | Out-Null }
  if ($LinkedServiceType -eq "AzureFunction") { $cats.Add("AzureFunction_ActivityOrLS$suffix") | Out-Null }

  # IR-driven categories
  if ($IrClass -eq "SelfHosted") { $cats.Add("SHIR$suffix") | Out-Null }
  if ($IrClass -eq "AzureSSIS")  { $cats.Add("AzureSSIS$suffix") | Out-Null }

  if ($cats.Count -eq 0) {
    if ($suffix) { $cats.Add("Other$suffix") | Out-Null }
    else { $cats.Add("Other") | Out-Null }
  }

  return ($cats -join ';')
}

function Invoke-ArmGetJson {
  <#
    Uses the current Az context to call ARM and return JSON as PSObject.
    The ADF REST endpoints used are documented here: Linked Services list-by-factory and IR list-by-factory. [3](https://learn.microsoft.com/en-us/rest/api/datafactory/integration-runtimes/list-by-factory?view=rest-datafactory-2018-06-01)
  #>
  param([string]$Url)

  $resp = Invoke-AzRestMethod -Method GET -Uri $Url
  if (-not $resp.Content) { return $null }
  return ($resp.Content | ConvertFrom-Json)
}

# ----------------------------
# Preconditions / Modules
# ----------------------------
Ensure-Module -Name "Az.Accounts"
Ensure-Module -Name "Az.ResourceGraph"

if (-not (Get-AzContext)) {
  Write-Host "Connecting to Azure..."
  Connect-AzAccount | Out-Null
}

# Determine subscriptions
$subsToScan = @()
if ($SubscriptionId) {
  $subsToScan = @($SubscriptionId)
} else {
  $subsToScan = (Get-AzSubscription | Select-Object -ExpandProperty Id)
}

if (-not $subsToScan -or $subsToScan.Count -eq 0) {
  throw "No subscriptions found to scan."
}

Write-Host "Scanning subscriptions: $($subsToScan.Count)"

# ----------------------------
# Resource Graph Inventory
# ----------------------------

# Storage Accounts (name -> config)
$storageQuery = @"
Resources
| where type =~ 'microsoft.storage/storageaccounts'
| where subscriptionId in~ ('$(($subsToScan -join "','"))')
| project subscriptionId, name,
          bypass=tostring(properties.networkAcls.bypass),
          defaultAction=tostring(properties.networkAcls.defaultAction),
          pna=tostring(properties.publicNetworkAccess)
"@

$storRows = Get-AllAzGraph -Query $storageQuery -Subscriptions $subsToScan
$storageMap = @{}
foreach ($r in $storRows) {
  $storageMap[$r.name.ToLowerInvariant()] = @{
    subscriptionId = $r.subscriptionId
    bypass         = $r.bypass
    defaultAction  = $r.defaultAction
    pna            = $r.pna
  }
}

# Key Vaults (name -> config)
$kvQuery = @"
Resources
| where type =~ 'microsoft.keyvault/vaults'
| where subscriptionId in~ ('$(($subsToScan -join "','"))')
| project subscriptionId, name,
          bypass=tostring(properties.networkAcls.bypass),
          defaultAction=tostring(properties.networkAcls.defaultAction),
          pna=tostring(properties.publicNetworkAccess)
"@

$kvRows = Get-AllAzGraph -Query $kvQuery -Subscriptions $subsToScan
$kvMap = @{}
foreach ($r in $kvRows) {
  $kvMap[$r.name.ToLowerInvariant()] = @{
    subscriptionId = $r.subscriptionId
    bypass         = $r.bypass
    defaultAction  = $r.defaultAction
    pna            = $r.pna
  }
}

# Data Factories
$adfQuery = @"
Resources
| where type =~ 'microsoft.datafactory/factories'
| where subscriptionId in~ ('$(($subsToScan -join "','"))')
| project subscriptionId, resourceGroup, name
| order by subscriptionId, resourceGroup, name
"@

$factories = Get-AllAzGraph -Query $adfQuery -Subscriptions $subsToScan

Write-Host "Found ADF factories: $($factories.Count)"

# ----------------------------
# Build the report rows
# ----------------------------
$report = New-Object System.Collections.Generic.List[object]

foreach ($f in $factories) {
  $subId = $f.subscriptionId
  $rg    = $f.resourceGroup
  $df    = $f.name

  # Set context per subscription so Invoke-AzRestMethod uses the right sub
  Set-AzContext -SubscriptionId $subId | Out-Null

  # ADF Integration Runtimes - List By Factory [3](https://learn.microsoft.com/en-us/rest/api/datafactory/integration-runtimes/list-by-factory?view=rest-datafactory-2018-06-01)
  $irUrl = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.DataFactory/factories/$df/integrationRuntimes?api-version=$ApiVersion"
  $irJson = Invoke-ArmGetJson -Url $irUrl

  $irByName = @{}
  $irAllSummary = @()

  if ($irJson -and $irJson.value) {
    foreach ($ir in $irJson.value) {
      $irClass = Get-IrClass -IrProps $ir.properties
      $irByName[$ir.name] = $irClass
      $irAllSummary += ("{0}:{1}" -f $ir.name, (if ($ir.properties.type) { $ir.properties.type } else { "Unknown" }))
    }
  }

  $irAllJoined = ($irAllSummary -join ';')

  # ADF Linked Services - List By Factory 
  $lsUrl = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.DataFactory/factories/$df/linkedservices?api-version=$ApiVersion"
  $lsJson = Invoke-ArmGetJson -Url $lsUrl

  if (-not $lsJson -or -not $lsJson.value) { continue }

  foreach ($ls in $lsJson.value) {
    $lsName = $ls.name
    $lsType = $ls.properties.type
    $authType = $ls.properties.typeProperties.authenticationType

    # connectVia IR
    $connectVia = $ls.properties.connectVia.referenceName
    $connectViaIR = if ($connectVia) { $connectVia } else { "(default Azure IR)" }
    $connectViaClass = if ($connectVia -and $irByName.ContainsKey($connectVia)) { $irByName[$connectVia] } elseif ($connectVia) { "Unknown" } else { "AzureIR" }

    # target URI best-effort (not all connectors expose it; parameterised LS may be blank)
    $tp = $ls.properties.typeProperties
    $targetUri = $null
    if ($tp) {
      if ($tp.url) { $targetUri = $tp.url }
      elseif ($tp.baseUrl) { $targetUri = $tp.baseUrl }
      elseif ($tp.serviceEndpoint) { $targetUri = $tp.serviceEndpoint }
    }

    $uriHost = Parse-HostFromUri -Uri $targetUri
    $targetKind = Classify-TargetKind -Hostname $uriHost
    $targetName = if ($uriHost) { $uriHost.Split('.')[0] } else { "" }

    # Join target to maps
    $targetPna = ""
    $targetDefaultAction = ""
    $targetBypass = ""
    $trustedConfigured = "?"
    $trustedEffective  = "?"

    if ($targetKind -eq "Storage" -and $targetName) {
      $k = $targetName.ToLowerInvariant()
      if ($storageMap.ContainsKey($k)) {
        $entry = $storageMap[$k]
        $targetBypass = $entry.bypass
        $targetDefaultAction = $entry.defaultAction
        $targetPna = Normalize-Pna -PublicNetworkAccess $entry.pna

        $trustedConfigured = if ($targetBypass -and $targetBypass -ieq "AzureServices") { "Y" } else { "N" }
        $trustedEffective  = if ($targetBypass -ieq "AzureServices" -and $targetPna -ine "Disabled" -and $targetDefaultAction -ieq "Deny") { "Y" } else { "N" }
      }
    }
    elseif ($targetKind -eq "KeyVault" -and $targetName) {
      $k = $targetName.ToLowerInvariant()
      if ($kvMap.ContainsKey($k)) {
        $entry = $kvMap[$k]
        $targetBypass = $entry.bypass
        $targetDefaultAction = $entry.defaultAction
        $targetPna = Normalize-Pna -PublicNetworkAccess $entry.pna

        $trustedConfigured = if ($targetBypass -and $targetBypass -ieq "AzureServices") { "Y" } else { "N" }
        $trustedEffective  = if ($targetBypass -ieq "AzureServices" -and $targetPna -ine "Disabled" -and $targetDefaultAction -ieq "Deny") { "Y" } else { "N" }
      }
    }

    $scenarioCategory = Build-ScenarioCategory -LinkedServiceType $lsType -IrClass $connectViaClass -TargetKind $targetKind

    $report.Add([pscustomobject]@{
      subscriptionId             = $subId
      resourceGroup              = $rg
      factoryName                = $df
      linkedServiceName          = $lsName
      linkedServiceType          = $lsType
      authType                   = $authType
      connectViaIR               = $connectViaIR
      connectViaIRClass          = $connectViaClass
      scenarioCategory           = $scenarioCategory
      targetUri                  = $targetUri
      targetKind                 = $targetKind
      targetName                 = $targetName
      targetPna                  = $targetPna
      targetDefaultAction        = $targetDefaultAction
      targetBypass               = $targetBypass
      trustedBypassConfigured    = $trustedConfigured
      trustedBypassEffective     = $trustedEffective
      integrationRuntimesAll     = $irAllJoined
    }) | Out-Null
  }
}

# Export
$report | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
Write-Host "Done. Wrote: $OutputPath"
