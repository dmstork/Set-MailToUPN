# User ActiveDirectory
$Check = Get-Command -Module ActiveDirectory
If ($Null -eq $Check){
    Write-Output "Error: Active Directory PowerShell module is not installed on this machine. Stopping."
    Break
} else {
    Import-Module ActiveDirectory
}

# Import CSV with accounts, column SamAccountname
#$Accounts = Import-CSV -Path "Accounts.txt"
#$Accounts = Import-CSV -Path "export.txt"


# is it synced? mS-DS-ConsistencyGuid
# Does it have an on-prem mailbox? msExchMailboxGuid
# Does it have mailadresses? proxyAddresses (iffy)

$Accounts =  Get-ADUser -Filter "msExchMailboxGuid -like '*'" | Where {($_.DistinguishedName -notlike "*CN=Microsoft Exchange System Objects*") -xor ($_.DistinguishedName -notlike "CN=DiscoverySearchMailbox {*") -xor ($_.DistinguishedName -notlike "CN=FederatedEmail.*") -xor ($_.DistinguishedName -notlike "CN=Migration.*") -xor ($_.DistinguishedName -notlike "CN=SystemMailbox{*")}

$FoundAccounts = @()
$NoPrimarySMTP = @()

# Export current account settings (backup)
#   Current UPN, SamAccountname, PrimaryMail
Write-Output "--"
Write-Output "SamAccountName, UserPrincipalName, PrimarySMTPAddress"

ForEach ($Account in $Accounts){
    $Identity = [String]$Account.SamAccountname
    # Write-Output "Identity is $Identity"
    $PrimaryAddress = Get-ADUser -Identity $Identity -Properties ProxyAddresses | Select -Expand proxyAddresses | Where {$_ -clike "SMTP:*"}
    
    If ($null -ne $PrimaryAddress){
        $PrimaryAddress = $PrimaryAddress.SubString(5)
        $UserPrincipalName = [String]$Account.UserPrincipalName
    
        $CurrentUser = [PSCustomObject] @{
            SamAccountname=$Identity
            UserPrincipalName=$UserPrincipalName
            PrimaryAddress=$PrimaryAddress
        }
        
        Write-Output "$Identity $UserPrincipalName $PrimaryAddress "
        $FoundAccounts += $CurrentUser

    } else {

        $UserPrincipalName = [String]$Account.UserPrincipalName
            
        $NoSMTPUser = [PSCustomObject] @{
            SamAccountname=$Identity
            UserPrincipalName=$UserPrincipalName
        }
        
        $NoPrimarySMTP += $NoSMTPUser
    }
   

# create export CSV append
}

$FoundAccounts #| Export-CSV -NoTypeInformation -Path export.txt

Write-Output "No Primary SMTP found:"
$NoPrimarySMTP