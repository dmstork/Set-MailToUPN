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
   
}


#Get date for export
$LogTime = Get-Date -Format "yyyyMMdd"

#Export to files
$FoundAccounts | Export-CSV -NoTypeInformation -Path $logtime"Mailboxes.txt"
$NoPrimarySMTP | Export-CSV -NoTypeInformation -Path $logtime"NoPrimarySMTP.txt"