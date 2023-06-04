If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

#Removing any old rules
$firewallRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -eq "Block Bad IPs"} 

if ($firewallRules) {
    foreach ($rule in $firewallRules) {
        Remove-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
    }
  }



function Get-IPAddressesFromList1($csvString) {
    $ipAddresses = @()

    # Split the CSV string into lines
    $lines = $csvString -split "\r?\n"

    # Extract IP addresses
    foreach ($line in $lines) {
        # Skip empty lines and comment lines
        if ($line -notmatch "^\s*(#|$)") {
            # Extract the IP address from the appropriate field
            if ($line -match '"[^"]*","([^"]+)"') {
                $ip = $matches[1].Trim()
                $ipAddresses += $ip
            }
        }
    }
    $ipAddresses = $ipAddresses | Select-Object -Skip 1
    return $ipAddresses
}

function Get-IPAddressesFromList2($csvString) {
    $ipAddresses = @()

    # Split the CSV string into lines
    $lines = $csvString -split "\r?\n"

    # Extract IP addresses
    foreach ($line in $lines) {
        # Skip empty lines and comment lines
        if ($line -notmatch "^\s*(#|$)") {
            # Extract the IP address from the appropriate field
            if ($line -match 'http://([\d.]+):') {
                $ip = $matches[1].Trim()
                $ipAddresses += $ip
            }
        }
    }

    return $ipAddresses
}



function Get-IPAddressesFromList3($list){

$pattern = '\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'

$matches = [regex]::Matches($list, $pattern)
$ipAddresses = $matches | ForEach-Object { $_.Value }
return $ipAddresses


}


# Function to create a firewall rule to block multiple IP addresses
function New-FirewallRule($ipAddresses, $direction) {
    $action = "Block"
    $ruleName = "Block Bad IPs"

    

    # Create the rule
    $rule = New-NetFirewallRule -DisplayName $ruleName -Direction $direction -LocalPort Any -Protocol Any -Action $action -RemoteAddress $ipAddresses -Enabled True -Profile Any -Description "Blocking multiple IP addresses"

    # Apply the rule immediately
    $rule | Set-NetFirewallRule -PassThru
}

# URLs to query
$url1 = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
$url2 = "https://urlhaus.abuse.ch/downloads/csv_online/"
$url3 = "https://www.spamhaus.org/drop/drop.txt"

# Query the URLs and get the CSV content
$csvContent1 = Invoke-WebRequest -Uri $url1 -UseBasicParsing | Select-Object -ExpandProperty Content 
$csvContent2 = Invoke-WebRequest -Uri $url2 -UseBasicParsing | Select-Object -ExpandProperty Content 
$txtContent = Invoke-WebRequest -Uri $url3 -UseBasicParsing | Select-Object -ExpandProperty Content

# Extract IP addresses from CSV content
$ipAddresses1 = Get-IPAddressesFromList1 $csvContent1
$ipAddresses2 = Get-IPAddressesFromList2 $csvContent2
$ipAddresses3 = Get-IPAddressesFromList3 $txtContent



# Create inbound and outbound rules for list 1
New-FirewallRule $ipAddresses1 "Inbound"
New-FirewallRule $ipAddresses1 "Outbound"


# Create inbound and outbound rules for list 2
New-FirewallRule $ipAddresses2 "Inbound"
New-FirewallRule $ipAddresses2 "Outbound"

# Create inbound and outbound rules for list 3
New-FirewallRule $ipAddresses3 "Inbound"
New-FirewallRule $ipAddresses3 "Outbound"
