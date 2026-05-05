<#
.SYNOPSIS
  Produces a broad ADF managed identity + trusted services bypass candidate risk report.

.DESCRIPTION
  Stage 1 discovery script for the Azure Data Factory managed identity + trusted services
  firewall bypass retirement scenario. This script intentionally produces a broad candidate
  report, not a definitive affected-services list.

  - Uses Azure Resource Graph to inventory:
      * Storage accounts: networkAcls.bypass, networkAcls.defaultAction, publicNetworkAccess
      * Key Vaults:      networkAcls.bypass, networkAcls.defaultAction, publicNetworkAccess
      * Data Factories: identity.type and user-assigned identity presence
    Default AuthMode uses Azure CLI and the Resource Graph REST endpoint.
    AzPowerShell mode uses Search-AzGraph.

  - Uses Azure Data Factory REST APIs:
      * Linked Services - List By Factory (api-version 2018-06-01) 
      * Integration Runtimes - List By Factory (api-version 2018-06-01) [3](https://learn.microsoft.com/en-us/rest/api/datafactory/integration-runtimes/list-by-factory?view=rest-datafactory-2018-06-01)
    ADF list operations follow nextLink pagination.

  - Correlates linked service URL/baseUrl/serviceEndpoint values with Storage and Key Vault
    firewall settings where the target URI can be directly derived.

  - Adds candidate evidence fields:
      * factoryIdentityType, factoryHasSystemAssignedMI, factoryHasUserAssignedMI
      * usesManagedIdentity, derived best-effort from linked service authenticationType
      * targetDetectionStatus: Direct, Parameterized, NotFound, or Unknown
      * trustedBypassConfigured and trustedBypassEffective
      * riskLevel and reasonCodes

  riskLevel is conservative:
      * High: Storage/KeyVault target + trusted bypass effective + managed identity evidence
      * Medium: Storage/KeyVault target + trusted bypass effective, but MI evidence is incomplete
      * Low: broader candidate signal or incomplete evidence

  Parameterized targets, REST/Web/AzureFunction-style linked service signals, and IR patterns
  may require pipeline/activity inspection outside this script. Use Get-AffectedServices.ps1
  as the stage-2 reducer for a narrower likely affected/manual-review CSV.

.PARAMETER SubscriptionId
  Optional. If supplied, scans only that subscription. Otherwise scans all accessible subscriptions.

.PARAMETER TenantId
  Optional. Validates that Azure CLI is using the expected tenant when AuthMode is AzureCli.
  In AzPowerShell mode, it is passed to Connect-AzAccount / Set-AzContext.

.PARAMETER AccountId
  Optional. User principal name/account to use for Connect-AzAccount when AuthMode is AzPowerShell.

.PARAMETER AuthMode
  Authentication source. Defaults to AzureCli, which uses the account from az login.
  AzPowerShell uses Connect-AzAccount and Az PowerShell context instead.

.PARAMETER OutputPath
  Output CSV path.

.EXAMPLE
  .\Get-AdfTrustedBypassRiskReport.ps1
  Uses the current Azure CLI account, scans all enabled Azure CLI subscriptions, and writes .\adf_risk_report_v3_pwsh.csv

.EXAMPLE
  .\Get-AdfTrustedBypassRiskReport.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -OutputPath "C:\temp\adf.csv"

.EXAMPLE
  .\Get-AdfTrustedBypassRiskReport.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -TenantId "11111111-1111-1111-1111-111111111111"

.EXAMPLE
  .\Get-AdfTrustedBypassRiskReport.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -TenantId "11111111-1111-1111-1111-111111111111" -AccountId "user@contoso.com" -AuthMode AzPowerShell
#>

param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

  [Parameter(Mandatory = $false)]
  [string]$AccountId,

  [Parameter(Mandatory = $false)]
  [ValidateSet("AzureCli", "AzPowerShell")]
  [string]$AuthMode = "AzureCli",

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

  Import-Module $Name -ErrorAction Stop
}

function Assert-AzModuleSessionClean {
  $legacyModules = Get-Module AzureRM*, Azure -ErrorAction SilentlyContinue
  if ($legacyModules) {
    $loaded = ($legacyModules | Select-Object -ExpandProperty Name -Unique) -join ', '
    throw "Legacy Azure PowerShell module(s) are loaded in this session: $loaded. Start a fresh PowerShell session with -NoProfile, then load only Az modules."
  }
}

function Invoke-AzCommandWithHelpfulError {
  param(
    [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
    [Parameter(Mandatory=$true)][string]$Operation
  )

  try {
    & $ScriptBlock
  }
  catch {
    if ($_.Exception.Message -like "*get_SerializationSettings*ResourceManagementClient*") {
      throw @"
Az module assembly conflict while running: $Operation

PowerShell has loaded incompatible Azure assemblies. Start a fresh shell with:
  pwsh -NoProfile

Then update/reinstall the Az modules used by this script:
  Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser -Repository PSGallery -Force -AllowClobber

If the error persists, remove old AzureRM/Azure modules from your profile/session before running this script.
Original error: $($_.Exception.Message)
"@
    }

    if ($Operation -like "Search-AzGraph*" -and $_.Exception.Message -like "*AccessDenied*") {
      $ctx = Get-AzContext -ErrorAction SilentlyContinue
      $account = if ($ctx.Account.Id) { $ctx.Account.Id } else { "(unknown)" }
      $tenant = if ($ctx.Tenant.Id) { $ctx.Tenant.Id } else { "(unknown)" }
      $subscription = if ($ctx.Subscription.Id) { $ctx.Subscription.Id } else { "(unknown)" }

      throw @"
Azure Resource Graph access denied while running: $Operation

Signed-in account: $account
Current tenant:    $tenant
Current sub:       $subscription

The account needs read access to the subscription being scanned. Ask for at least Reader on the subscription, or sign in to the tenant that owns the subscription:
  Connect-AzAccount -Tenant <tenant-id>
  Set-AzContext -Subscription <subscription-id>

Original error: $($_.Exception.Message)
"@
    }

    if ($Operation -like "Set-AzContext*" -and $_.Exception.Message -like "*valid tenant*valid subscription*") {
      $ctx = Get-AzContext -ErrorAction SilentlyContinue
      $account = if ($ctx.Account.Id) { $ctx.Account.Id } else { "(unknown)" }
      $tenant = if ($ctx.Tenant.Id) { $ctx.Tenant.Id } else { "(unknown)" }

      throw @"
Azure context could not be set while running: $Operation

Signed-in account: $account
Current tenant:    $tenant

The subscription was not found in the current login context. If this subscription belongs to a different tenant, run the script with -TenantId:
  .\Get-AdfTrustedBypassRiskReport.ps1 -SubscriptionId "$SubscriptionId" -TenantId "<tenant-id>" -AccountId "<account-upn>"

You can verify visibility with:
  Get-AzSubscription -SubscriptionId "$SubscriptionId"

Original error: $($_.Exception.Message)
"@
    }

    throw
  }
}

function Get-AzLoginParams {
  $loginParams = @{}

  if ($SubscriptionId) {
    $loginParams.Subscription = $SubscriptionId
    $loginParams.MaxContextPopulation = 1
  }

  if ($TenantId) {
    $loginParams.Tenant = $TenantId
    $loginParams.MaxContextPopulation = 1
  }

  if ($AccountId) {
    $loginParams.AccountId = $AccountId
  }

  return $loginParams
}

function Test-AzContextMatchesTarget {
  $ctx = Get-AzContext -ErrorAction SilentlyContinue
  if (-not $ctx) { return $false }

  if ($SubscriptionId -and $ctx.Subscription.Id -ne $SubscriptionId) { return $false }
  if ($TenantId -and $ctx.Tenant.Id -ne $TenantId) { return $false }
  if ($AccountId -and $ctx.Account.Id -ne $AccountId) { return $false }

  return $true
}

function Connect-AzForTarget {
  $loginParams = Get-AzLoginParams

  try {
    Invoke-AzCommandWithHelpfulError -Operation "Connect-AzAccount" -ScriptBlock {
      Connect-AzAccount @loginParams | Out-Null
    }
  }
  catch {
    if ($_.Exception.Message -like "*Az module assembly conflict*" -or $_.Exception.Message -like "*get_SerializationSettings*ResourceManagementClient*") {
      throw
    }

    Write-Warning "Browser-based Azure sign-in failed. Falling back to device-code sign-in."
    Invoke-AzCommandWithHelpfulError -Operation "Connect-AzAccount -UseDeviceAuthentication" -ScriptBlock {
      Connect-AzAccount @loginParams -UseDeviceAuthentication | Out-Null
    }
  }
}

function Invoke-AzCliJson {
  param(
    [Parameter(Mandatory=$true)][string[]]$Arguments,
    [Parameter(Mandatory=$true)][string]$Operation
  )

  $previousErrorActionPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $output = & az @Arguments 2>&1
  }
  finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }

  if ($LASTEXITCODE -ne 0) {
    throw "Azure CLI command failed while running: $Operation`n$($output -join [Environment]::NewLine)"
  }

  $json = ($output -join "`n").Trim()
  if ([string]::IsNullOrWhiteSpace($json)) { return $null }
  return ($json | ConvertFrom-Json)
}

function Ensure-AzureCliContext {
  if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI 'az' was not found. Install Azure CLI or rerun with -AuthMode AzPowerShell."
  }

  if ($SubscriptionId) {
    Invoke-AzCliJson -Operation "az account set" -Arguments @("account", "set", "--subscription", $SubscriptionId, "--only-show-errors") | Out-Null
  }

  $account = Invoke-AzCliJson -Operation "az account show" -Arguments @("account", "show", "--output", "json", "--only-show-errors")
  if (-not $account) {
    throw "Azure CLI is not logged in. Run: az login --use-device-code"
  }

  if ($TenantId -and $account.tenantId -ne $TenantId) {
    throw "Azure CLI is logged into tenant '$($account.tenantId)', but TenantId '$TenantId' was requested. Run: az login --use-device-code --tenant $TenantId"
  }

  Write-Host "Using Azure CLI account: $($account.user.name)"
  Write-Host "Azure CLI tenant: $($account.tenantId)"
  Write-Host "Azure CLI sub: $($account.id)"
}

function Get-AzureCliSubscriptions {
  $accounts = Invoke-AzCliJson -Operation "az account list" -Arguments @("account", "list", "--query", "[?state=='Enabled'].id", "--output", "json", "--only-show-errors")
  return @($accounts)
}

function Invoke-AzureCliResourceGraph {
  param(
    [Parameter(Mandatory=$true)][string]$Query,
    [Parameter(Mandatory=$true)][string[]]$Subscriptions
  )

  $results = @()
  $skipToken = $null
  $url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"

  do {
    $options = @{
      resultFormat = "objectArray"
      '$top'       = 1000
    }

    if ($skipToken) {
      $options.'$skipToken' = $skipToken
    }

    $body = @{
      subscriptions = $Subscriptions
      query         = $Query
      options       = $options
    } | ConvertTo-Json -Depth 10 -Compress

    $bodyFile = New-TemporaryFile
    try {
      Set-Content -LiteralPath $bodyFile.FullName -Value $body -Encoding UTF8

      $resp = Invoke-AzCliJson -Operation "Azure Resource Graph REST query" -Arguments @(
        "rest",
        "--method", "post",
        "--url", $url,
        "--headers", "Content-Type=application/json",
        "--body", "@$($bodyFile.FullName)",
        "--output", "json",
        "--only-show-errors"
      )
    }
    finally {
      Remove-Item -LiteralPath $bodyFile.FullName -Force -ErrorAction SilentlyContinue
    }

    if ($resp.data) { $results += $resp.data }
    $skipToken = $resp.'$skipToken'
    if (-not $skipToken) { $skipToken = $resp.skipToken }
  } while ($skipToken)

  return $results
}

function Get-AllAzGraph {
  <#
    Executes an Azure Resource Graph query across provided subscriptions.
    AzureCli mode uses the Resource Graph REST endpoint. AzPowerShell mode uses Search-AzGraph.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$Query,
    [Parameter(Mandatory=$false)][string[]]$Subscriptions
  )

  if ($AuthMode -eq "AzureCli") {
    if (-not $Subscriptions -or $Subscriptions.Count -eq 0) {
      throw "AzureCli AuthMode requires an explicit subscription list."
    }

    return (Invoke-AzureCliResourceGraph -Query $Query -Subscriptions $Subscriptions)
  }

  $results = @()
  $skipToken = $null

  do {
    if ($Subscriptions -and $Subscriptions.Count -gt 0) {
      if ($skipToken) {
        $resp = Invoke-AzCommandWithHelpfulError -Operation "Search-AzGraph" -ScriptBlock {
          Search-AzGraph -Query $Query -Subscription $Subscriptions -First 1000 -SkipToken $skipToken
        }
      } else {
        $resp = Invoke-AzCommandWithHelpfulError -Operation "Search-AzGraph" -ScriptBlock {
          Search-AzGraph -Query $Query -Subscription $Subscriptions -First 1000
        }
      }
    } else {
      # tenant-scope (if allowed) – may require additional permissions
      if ($skipToken) {
        $resp = Invoke-AzCommandWithHelpfulError -Operation "Search-AzGraph tenant scope" -ScriptBlock {
          Search-AzGraph -Query $Query -UseTenantScope -AllowPartialScope -First 1000 -SkipToken $skipToken
        }
      } else {
        $resp = Invoke-AzCommandWithHelpfulError -Operation "Search-AzGraph tenant scope" -ScriptBlock {
          Search-AzGraph -Query $Query -UseTenantScope -AllowPartialScope -First 1000
        }
      }
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

function Test-BypassIncludesAzureServices {
  param([string]$Bypass)

  if ([string]::IsNullOrWhiteSpace($Bypass)) { return $false }

  # Resource providers may return comma/semicolon/space separated bypass values.
  $tokens = $Bypass -split '[,; ]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  return [bool]($tokens | Where-Object { $_ -ieq "AzureServices" } | Select-Object -First 1)
}

function ConvertTo-YesNo {
  param([bool]$Value)
  if ($Value) { return "Y" }
  return "N"
}

function Get-FactoryIdentitySummary {
  param(
    [string]$IdentityType,
    $UserAssignedIdentities
  )

  $identityTypeText = if ([string]::IsNullOrWhiteSpace($IdentityType)) { "None" } else { $IdentityType }
  $hasSystemAssigned = $identityTypeText -match 'SystemAssigned'
  $hasUserAssigned = $identityTypeText -match 'UserAssigned'

  if (-not $hasUserAssigned -and $null -ne $UserAssignedIdentities) {
    if ($UserAssignedIdentities -is [string]) {
      $hasUserAssigned = -not [string]::IsNullOrWhiteSpace($UserAssignedIdentities) -and $UserAssignedIdentities -ne "{}"
    } else {
      $props = @($UserAssignedIdentities.PSObject.Properties)
      $hasUserAssigned = $props.Count -gt 0
    }
  }

  return [pscustomobject]@{
    Type              = $identityTypeText
    HasSystemAssigned = ConvertTo-YesNo -Value $hasSystemAssigned
    HasUserAssigned   = ConvertTo-YesNo -Value $hasUserAssigned
  }
}

function Get-UsesManagedIdentity {
  param(
    [string]$AuthenticationType,
    [string]$LinkedServiceType
  )

  # Best-effort and intentionally extensible: start with common authType values and
  # leave connector-specific typeProperties inspection for a later, narrower pass.
  if ([string]::IsNullOrWhiteSpace($AuthenticationType)) { return "?" }
  if ($AuthenticationType -match '(?i)(managed|msi|systemassigned|userassigned)') { return "Y" }
  if ($AuthenticationType -match '(?i)(anonymous|basic|accountkey|accesskey|sas|serviceprincipal|clientcertificate|sql|windows)') { return "N" }
  return "?"
}

function Test-IsParameterizedValue {
  param($Value)

  if ($null -eq $Value) { return $false }

  if ($Value -is [string]) {
    return ($Value -match '^\s*@' -or $Value -match '@\{' -or $Value -match '(?i)linkedService\(\)\.parameters|parameters\(')
  }

  if ($Value.PSObject.Properties.Name -contains "type" -and $Value.type -match '(?i)Expression') {
    return $true
  }

  return (($Value | ConvertTo-Json -Depth 20 -Compress) -match '(?i)Expression|@\{|linkedService\(\)\.parameters|parameters\(')
}

function Get-LinkedServiceTargetInfo {
  param($TypeProperties)

  if (-not $TypeProperties) {
    return [pscustomobject]@{ Uri = $null; Status = "Unknown" }
  }

  foreach ($propName in @("url", "baseUrl", "serviceEndpoint")) {
    $prop = $TypeProperties.PSObject.Properties[$propName]
    if ($prop -and $null -ne $prop.Value) {
      if (Test-IsParameterizedValue -Value $prop.Value) {
        return [pscustomobject]@{ Uri = $null; Status = "Parameterized" }
      }

      return [pscustomobject]@{ Uri = [string]$prop.Value; Status = "Direct" }
    }
  }

  if (Test-IsParameterizedValue -Value $TypeProperties) {
    return [pscustomobject]@{ Uri = $null; Status = "Parameterized" }
  }

  return [pscustomobject]@{ Uri = $null; Status = "NotFound" }
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

  # Connector-driven categories. These are linked-service signals only; pipeline/activity
  # inspection is intentionally out of scope for this broad candidate report.
  if ($LinkedServiceType -eq "RestService")    { $cats.Add("REST_LinkedService$suffix") | Out-Null }
  if ($LinkedServiceType -eq "Web")           { $cats.Add("Web_LinkedServiceEvidence$suffix") | Out-Null }
  if ($LinkedServiceType -eq "AzureFunction") { $cats.Add("AzureFunction_LinkedServiceEvidence$suffix") | Out-Null }

  # IR-driven categories
  if ($IrClass -eq "SelfHosted") { $cats.Add("SHIR$suffix") | Out-Null }
  if ($IrClass -eq "AzureSSIS")  { $cats.Add("AzureSSIS$suffix") | Out-Null }

  if ($cats.Count -eq 0) {
    if ($suffix) { $cats.Add("Other$suffix") | Out-Null }
    else { $cats.Add("Other") | Out-Null }
  }

  return ($cats -join ';')
}

function Get-RiskAssessment {
  param(
    [string]$TargetKind,
    [string]$TrustedBypassEffective,
    [string]$UsesManagedIdentity,
    [string]$FactoryHasSystemAssignedMI,
    [string]$IrClass,
    [string]$LinkedServiceType
  )

  $reasonCodes = New-Object System.Collections.Generic.List[string]
  $targetIsStorageOrKeyVault = $TargetKind -eq "Storage" -or $TargetKind -eq "KeyVault"

  if ($targetIsStorageOrKeyVault) { $reasonCodes.Add("TargetIsStorageOrKeyVault") | Out-Null }
  if ($TrustedBypassEffective -eq "Y") { $reasonCodes.Add("TrustedBypassEffective") | Out-Null }
  if ($UsesManagedIdentity -eq "Y") { $reasonCodes.Add("LinkedServiceUsesManagedIdentity") | Out-Null }
  if ($FactoryHasSystemAssignedMI -eq "Y") { $reasonCodes.Add("FactoryHasSystemAssignedMI") | Out-Null }
  if ($IrClass -eq "SelfHosted") { $reasonCodes.Add("UsesSHIR") | Out-Null }
  if ($IrClass -eq "AzureSSIS") { $reasonCodes.Add("UsesAzureSSIS") | Out-Null }
  if ($LinkedServiceType -match '^(RestService|Web|AzureFunction)$') { $reasonCodes.Add("NeedsPipelineInspection") | Out-Null }

  $hasMiEvidence = $UsesManagedIdentity -eq "Y" -or $FactoryHasSystemAssignedMI -eq "Y"
  $riskLevel = "Low"
  if ($targetIsStorageOrKeyVault -and $TrustedBypassEffective -eq "Y" -and $hasMiEvidence) {
    $riskLevel = "High"
  }
  elseif ($targetIsStorageOrKeyVault -and $TrustedBypassEffective -eq "Y") {
    $riskLevel = "Medium"
  }

  return [pscustomobject]@{
    Level       = $riskLevel
    ReasonCodes = ($reasonCodes -join ';')
  }
}

function Invoke-ArmGetJson {
  <#
    Uses the current Az context to call ARM and return JSON as PSObject.
    The ADF REST endpoints used are documented here: Linked Services list-by-factory and IR list-by-factory. [3](https://learn.microsoft.com/en-us/rest/api/datafactory/integration-runtimes/list-by-factory?view=rest-datafactory-2018-06-01)
  #>
  param([string]$Url)

  if ($AuthMode -eq "AzureCli") {
    return (Invoke-AzCliJson -Operation "az rest GET $Url" -Arguments @(
      "rest",
      "--method", "get",
      "--url", $Url,
      "--output", "json",
      "--only-show-errors"
    ))
  }

  $resp = Invoke-AzCommandWithHelpfulError -Operation "Invoke-AzRestMethod GET $Url" -ScriptBlock {
    Invoke-AzRestMethod -Method GET -Uri $Url
  }
  if (-not $resp.Content) { return $null }
  return ($resp.Content | ConvertFrom-Json)
}

function Get-ArmPagedValues {
  param([string]$Url)

  $values = @()
  $nextUrl = $Url

  while ($nextUrl) {
    $json = Invoke-ArmGetJson -Url $nextUrl
    if ($json -and $json.value) {
      $values += @($json.value)
    }

    $nextUrl = $null
    if ($json -and $json.nextLink) {
      $nextUrl = $json.nextLink
    }
  }

  return $values
}

# ----------------------------
# Preconditions / Modules
# ----------------------------
if ($AuthMode -eq "AzureCli") {
  Ensure-AzureCliContext
} else {
  Assert-AzModuleSessionClean
  Ensure-Module -Name "Az.Accounts"
  Ensure-Module -Name "Az.ResourceGraph"

  if (-not (Test-AzContextMatchesTarget)) {
    if (Get-AzContext -ErrorAction SilentlyContinue) {
      Write-Host "Current Az PowerShell context does not match the requested target. Reconnecting..."
    } else {
      Write-Host "Connecting to Azure..."
    }

    Connect-AzForTarget
  }
}

# Determine subscriptions
$subsToScan = @()
if ($SubscriptionId) {
  $subsToScan = @($SubscriptionId)
} else {
  if ($AuthMode -eq "AzureCli") {
    $subsToScan = Get-AzureCliSubscriptions
  } else {
    $subsToScan = (Get-AzSubscription | Select-Object -ExpandProperty Id)
  }
}

if (-not $subsToScan -or $subsToScan.Count -eq 0) {
  throw "No subscriptions found to scan."
}

if ($AuthMode -eq "AzPowerShell" -and $SubscriptionId) {
  Invoke-AzCommandWithHelpfulError -Operation "Set-AzContext $SubscriptionId" -ScriptBlock {
    if ($TenantId) {
      Set-AzContext -Subscription $SubscriptionId -Tenant $TenantId | Out-Null
    } else {
      Set-AzContext -Subscription $SubscriptionId | Out-Null
    }
  }
}

if ($AuthMode -eq "AzPowerShell") {
  $azContext = Get-AzContext
  if ($azContext) {
    Write-Host "Signed in as: $($azContext.Account.Id)"
    Write-Host "Current tenant: $($azContext.Tenant.Id)"
    Write-Host "Current sub: $($azContext.Subscription.Id)"
  }
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
| project subscriptionId, resourceGroup, name,
          identityType=tostring(identity.type),
          userAssignedIdentities=identity.userAssignedIdentities
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
  $factoryIdentity = Get-FactoryIdentitySummary -IdentityType $f.identityType -UserAssignedIdentities $f.userAssignedIdentities

  if ($AuthMode -eq "AzPowerShell") {
    # Set context per subscription so Invoke-AzRestMethod uses the right sub
    Invoke-AzCommandWithHelpfulError -Operation "Set-AzContext $subId" -ScriptBlock {
      if ($TenantId) {
        Set-AzContext -Subscription $subId -Tenant $TenantId | Out-Null
      } else {
        Set-AzContext -Subscription $subId | Out-Null
      }
    }
  }

  # ADF Integration Runtimes - List By Factory [3](https://learn.microsoft.com/en-us/rest/api/datafactory/integration-runtimes/list-by-factory?view=rest-datafactory-2018-06-01)
  $irUrl = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.DataFactory/factories/$df/integrationRuntimes?api-version=$ApiVersion"
  $irRows = Get-ArmPagedValues -Url $irUrl

  $irByName = @{}
  $irAllSummary = @()

  if ($irRows) {
    foreach ($ir in $irRows) {
      $irClass = Get-IrClass -IrProps $ir.properties
      $irByName[$ir.name] = $irClass
      $irAllSummary += ("{0}:{1}" -f $ir.name, (if ($ir.properties.type) { $ir.properties.type } else { "Unknown" }))
    }
  }

  $irAllJoined = ($irAllSummary -join ';')

  # ADF Linked Services - List By Factory 
  $lsUrl = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.DataFactory/factories/$df/linkedservices?api-version=$ApiVersion"
  $lsRows = Get-ArmPagedValues -Url $lsUrl

  if (-not $lsRows) { continue }

  foreach ($ls in $lsRows) {
    $lsName = $ls.name
    $lsType = $ls.properties.type
    $authType = $ls.properties.typeProperties.authenticationType
    $usesManagedIdentity = Get-UsesManagedIdentity -AuthenticationType $authType -LinkedServiceType $lsType

    # connectVia IR
    $connectVia = $ls.properties.connectVia.referenceName
    $connectViaIR = if ($connectVia) { $connectVia } else { "(default Azure IR)" }
    $connectViaClass = if ($connectVia -and $irByName.ContainsKey($connectVia)) { $irByName[$connectVia] } elseif ($connectVia) { "Unknown" } else { "AzureIR" }

    # target URI best-effort (not all connectors expose it; parameterised LS may be blank)
    $tp = $ls.properties.typeProperties
    $targetInfo = Get-LinkedServiceTargetInfo -TypeProperties $tp
    $targetUri = $targetInfo.Uri
    $targetDetectionStatus = $targetInfo.Status

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

        $bypassIncludesAzureServices = Test-BypassIncludesAzureServices -Bypass $targetBypass
        $trustedConfigured = if ($bypassIncludesAzureServices) { "Y" } else { "N" }
        $trustedEffective  = if ($bypassIncludesAzureServices -and $targetPna -ine "Disabled" -and $targetDefaultAction -ieq "Deny") { "Y" } else { "N" }
      }
    }
    elseif ($targetKind -eq "KeyVault" -and $targetName) {
      $k = $targetName.ToLowerInvariant()
      if ($kvMap.ContainsKey($k)) {
        $entry = $kvMap[$k]
        $targetBypass = $entry.bypass
        $targetDefaultAction = $entry.defaultAction
        $targetPna = Normalize-Pna -PublicNetworkAccess $entry.pna

        $bypassIncludesAzureServices = Test-BypassIncludesAzureServices -Bypass $targetBypass
        $trustedConfigured = if ($bypassIncludesAzureServices) { "Y" } else { "N" }
        $trustedEffective  = if ($bypassIncludesAzureServices -and $targetPna -ine "Disabled" -and $targetDefaultAction -ieq "Deny") { "Y" } else { "N" }
      }
    }

    $scenarioCategory = Build-ScenarioCategory -LinkedServiceType $lsType -IrClass $connectViaClass -TargetKind $targetKind
    $risk = Get-RiskAssessment `
      -TargetKind $targetKind `
      -TrustedBypassEffective $trustedEffective `
      -UsesManagedIdentity $usesManagedIdentity `
      -FactoryHasSystemAssignedMI $factoryIdentity.HasSystemAssigned `
      -IrClass $connectViaClass `
      -LinkedServiceType $lsType

    $report.Add([pscustomobject]@{
      subscriptionId             = $subId
      resourceGroup              = $rg
      factoryName                = $df
      factoryIdentityType        = $factoryIdentity.Type
      factoryHasSystemAssignedMI = $factoryIdentity.HasSystemAssigned
      factoryHasUserAssignedMI   = $factoryIdentity.HasUserAssigned
      linkedServiceName          = $lsName
      linkedServiceType          = $lsType
      authType                   = $authType
      usesManagedIdentity        = $usesManagedIdentity
      connectViaIR               = $connectViaIR
      connectViaIRClass          = $connectViaClass
      scenarioCategory           = $scenarioCategory
      targetUri                  = $targetUri
      targetDetectionStatus      = $targetDetectionStatus
      targetKind                 = $targetKind
      targetName                 = $targetName
      targetPna                  = $targetPna
      targetDefaultAction        = $targetDefaultAction
      targetBypass               = $targetBypass
      trustedBypassConfigured    = $trustedConfigured
      trustedBypassEffective     = $trustedEffective
      riskLevel                  = $risk.Level
      reasonCodes                = $risk.ReasonCodes
      integrationRuntimesAll     = $irAllJoined
    }) | Out-Null
  }
}

# Export
$report | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
Write-Host "Done. Wrote: $OutputPath"
