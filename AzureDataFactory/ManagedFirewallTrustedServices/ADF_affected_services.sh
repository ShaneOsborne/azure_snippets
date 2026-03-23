#!/usr/bin/env bash
# adf_inventory_joined_v3.sh
# Output: adf_risk_report_v3.csv
#
# Adds scenarioCategory derived from:
# - linkedServiceType (RestService, Web, AzureFunction)
# - connectVia integration runtime class (SHIR/SelfHosted, AzureSSIS, AzureIR)
# - targetKind (Storage/KeyVault when URL is detectable)
#
# References:
# - ADF Linked Services REST list-by-factory (2018-06-01): https://learn.microsoft.com/en-us/rest/api/datafactory/linked-services/list-by-factory?view=rest-datafactory-2018-06-01
# - az datafactory integration-runtime list: https://learn.microsoft.com/en-us/cli/azure/datafactory/integration-runtime?view=azure-cli-latest
# - Storage firewall & trusted services exception: https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security
# - Key Vault networking & trusted services bypass: https://learn.microsoft.com/en-us/azure/key-vault/general/network-security

set -euo pipefail

SUBSCRIPTION_ID="${1:-$(az account show --query id -o tsv)}"
API_VERSION="2018-06-01"

OUT="adf_risk_report_v3.csv"

echo "subscriptionId,resourceGroup,factoryName,linkedServiceName,linkedServiceType,authType,connectViaIR,connectViaIRClass,scenarioCategory,targetUri,targetKind,targetName,targetPna,targetDefaultAction,targetBypass,trustedBypassConfigured,trustedBypassEffective,integrationRuntimesAll" > "$OUT"

echo "[1/5] Fetching Storage accounts network settings..." 1>&2
ST_DATA=$(az graph query -q "
Resources
| where type =~ 'microsoft.storage/storageaccounts'
| where subscriptionId == '${SUBSCRIPTION_ID}'
| extend bypass = tostring(properties.networkAcls.bypass)
| extend defaultAction = tostring(properties.networkAcls.defaultAction)
| extend pna = tostring(properties.publicNetworkAccess)
| project name, bypass, defaultAction, pna
" --query "data" -o json)

ST_MAP=$(echo "$ST_DATA" | jq -c '
  reduce .[] as $s ({}; . + {($s.name): {pna: ($s.pna//""), defaultAction: ($s.defaultAction//""), bypass: ($s.bypass//"")}})
')

echo "[2/5] Fetching Key Vault network settings..." 1>&2
KV_DATA=$(az graph query -q "
Resources
| where type =~ 'microsoft.keyvault/vaults'
| where subscriptionId == '${SUBSCRIPTION_ID}'
| extend bypass = tostring(properties.networkAcls.bypass)
| extend defaultAction = tostring(properties.networkAcls.defaultAction)
| extend pna = tostring(properties.publicNetworkAccess)
| project name, bypass, defaultAction, pna
" --query "data" -o json)

KV_MAP=$(echo "$KV_DATA" | jq -c '
  reduce .[] as $v ({}; . + {($v.name): {pna: ($v.pna//""), defaultAction: ($v.defaultAction//""), bypass: ($v.bypass//"")}})
')

echo "[3/5] Enumerating ADF factories..." 1>&2
ADF_FACTORIES=$(az graph query -q "
Resources
| where type =~ 'microsoft.datafactory/factories'
| where subscriptionId == '${SUBSCRIPTION_ID}'
| project subscriptionId, resourceGroup, name
| order by resourceGroup, name
" --query "data" -o json)

FACTORY_COUNT=$(echo "$ADF_FACTORIES" | jq 'length')
echo "Found $FACTORY_COUNT factories in subscription $SUBSCRIPTION_ID" 1>&2

parse_host () {
  local uri="$1"
  uri="${uri#http://}"; uri="${uri#https://}"
  echo "${uri%%/*}"
}

classify_target () {
  local host="$1"
  if [[ "$host" == *".vault."* ]]; then
    echo "KeyVault"
  elif [[ "$host" == *".blob."* || "$host" == *".dfs."* || "$host" == *".queue."* || "$host" == *".table."* ]]; then
    echo "Storage"
  else
    echo "Unknown"
  fi
}

pna_effective () {
  local pna="$1"
  if [[ -z "$pna" || "$pna" == "null" ]]; then
    echo "Enabled(implicit)"
  else
    echo "$pna"
  fi
}

# classify an IR record as one of: SelfHosted (SHIR), AzureSSIS, AzureIR
ir_class () {
  local ir_json="$1"
  local t; t=$(echo "$ir_json" | jq -r '.properties.type // ""')
  if [[ "$t" == "SelfHosted" ]]; then
    echo "SelfHosted"
    return
  fi

  # Azure-SSIS IRs are typically Managed IRs with ssisProperties present.
  # This heuristic works well for CLI output in most tenants.
  local has_ssis; has_ssis=$(echo "$ir_json" | jq -r '(.properties.typeProperties.ssisProperties != null) // false')
  if [[ "$has_ssis" == "true" ]]; then
    echo "AzureSSIS"
    return
  fi

  echo "AzureIR"
}

# scenarioCategory builder:
# - Prefer explicit connector categories (RestService/Web/AzureFunction) because they match the advisory wording
# - ALSO include IR class category (SHIR/AzureSSIS) when connectVia indicates it
# - Append target kind when known
scenario_build () {
  local lsType="$1"
  local irClass="$2"
  local targetKind="$3"

  local suffix=""
  if [[ "$targetKind" == "Storage" ]]; then suffix="_toStorage"; fi
  if [[ "$targetKind" == "KeyVault" ]]; then suffix="_toKeyVault"; fi

  local cats=()

  # Connector/activity classes from advisory
  if [[ "$lsType" == "RestService" ]]; then cats+=("REST_LinkedService${suffix}"); fi
  if [[ "$lsType" == "Web" ]]; then cats+=("Web_ActivityOrLS${suffix}"); fi
  if [[ "$lsType" == "AzureFunction" ]]; then cats+=("AzureFunction_ActivityOrLS${suffix}"); fi

  # IR classes from advisory
  if [[ "$irClass" == "SelfHosted" ]]; then cats+=("SHIR${suffix}"); fi
  if [[ "$irClass" == "AzureSSIS" ]]; then cats+=("AzureSSIS${suffix}"); fi

  if [[ "${#cats[@]}" -eq 0 ]]; then
    if [[ -n "$suffix" ]]; then
      cats+=("Other${suffix}")
    else
      cats+=("Other")
    fi
  fi

  (IFS=';'; echo "${cats[*]}")
}

for row in $(echo "$ADF_FACTORIES" | jq -r '.[] | @base64'); do
  _jq() { echo ${row} | base64 --decode | jq -r ${1}; }
  rg=$(_jq '.resourceGroup')
  factory=$(_jq '.name')

  echo "[4/5] Processing factory: $rg/$factory" 1>&2

  # List IRs for this factory (CLI)
  IR_JSON=$(az datafactory integration-runtime list -g "$rg" -f "$factory" 2>/dev/null || echo "[]")

  # Aggregate all IR types/classes (useful for high-level filtering)
  IR_ALL=$(echo "$IR_JSON" | jq -r 'map(.name + ":" + (.properties.type // "Unknown")) | join(";")')

  # Build IR map: irName -> class
  # Default IR in many factories is AutoResolveIntegrationRuntime; treat as AzureIR.
  IR_MAP=$(echo "$IR_JSON" | jq -c '
    reduce .[] as $ir ({}; . + {($ir.name): $ir})
  ')

  # Linked services via REST list-by-factory
  LS_URL="https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${rg}/providers/Microsoft.DataFactory/factories/${factory}/linkedservices?api-version=${API_VERSION}"
  LS_JSON=$(az rest --method get --url "$LS_URL")

  echo "$LS_JSON" | jq -c '.value[]' | while read -r ls; do
    lsName=$(echo "$ls" | jq -r '.name')
    lsType=$(echo "$ls" | jq -r '.properties.type')
    authType=$(echo "$ls" | jq -r '.properties.typeProperties.authenticationType // ""')

    # connectVia references an integration runtime by name (when set)
    connectViaIR=$(echo "$ls" | jq -r '.properties.connectVia.referenceName // ""')
    if [[ -z "$connectViaIR" ]]; then
      connectViaIR="(default Azure IR)"
      connectViaIRClass="AzureIR"
    else
      irObj=$(echo "$IR_MAP" | jq -c --arg n "$connectViaIR" '.[$n] // empty')
      if [[ -z "$irObj" ]]; then
        connectViaIRClass="Unknown"
      else
        connectViaIRClass=$(ir_class "$irObj")
      fi
    fi

    # Best-effort target URI
    targetUri=$(echo "$ls" | jq -r '
      .properties.typeProperties.url //
      .properties.typeProperties.baseUrl //
      .properties.typeProperties.serviceEndpoint //
      ""
    ')

    targetKind="Unknown"
    targetName=""
    targetPna=""
    targetDefaultAction=""
    targetBypass=""
    bypassConfigured="?"
    bypassEffective="?"

    if [[ -n "$targetUri" ]]; then
      host=$(parse_host "$targetUri")
      targetKind=$(classify_target "$host")
      targetName="${host%%.*}"

      if [[ "$targetKind" == "Storage" ]]; then
        entry=$(echo "$ST_MAP" | jq -c --arg n "$targetName" '.[$n] // empty')
      elif [[ "$targetKind" == "KeyVault" ]]; then
        entry=$(echo "$KV_MAP" | jq -c --arg n "$targetName" '.[$n] // empty')
      else
        entry=""
      fi

      if [[ -n "$entry" ]]; then
        rawPna=$(echo "$entry" | jq -r '.pna')
        targetPna=$(pna_effective "$rawPna")
        targetDefaultAction=$(echo "$entry" | jq -r '.defaultAction')
        targetBypass=$(echo "$entry" | jq -r '.bypass')

        if [[ "${targetBypass,,}" == "azureservices" ]]; then
          bypassConfigured="Y"
        else
          bypassConfigured="N"
        fi

        if [[ "${targetBypass,,}" == "azureservices" && "${targetPna,,}" != "disabled" && "${targetDefaultAction,,}" == "deny" ]]; then
          bypassEffective="Y"
        else
          bypassEffective="N"
        fi
      fi
    fi

    scenarioCategory=$(scenario_build "$lsType" "$connectViaIRClass" "$targetKind")

    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
      "$SUBSCRIPTION_ID" "$rg" "$factory" \
      "${lsName//,/;}" "${lsType//,/;}" "${authType//,/;}" \
      "${connectViaIR//,/;}" "${connectViaIRClass//,/;}" "${scenarioCategory//,/;}" \
      "${targetUri//,/;}" "$targetKind" "$targetName" \
      "${targetPna//,/;}" "${targetDefaultAction//,/;}" "${targetBypass//,/;}" \
      "$bypassConfigured" "$bypassEffective" \
      "${IR_ALL//,/;}" \
      >> "$OUT"
  done
done

echo "[5/5] Done. Output written to: $OUT" 1>&2