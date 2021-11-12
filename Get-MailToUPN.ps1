# User ActiveDirectory
$Check = Get-Command -Module ActiveDirectory
If ($Null -eq $Check){
    Write-Output "Error: Active Directory PowerShell module is not installed on this machine. Stopping."
    Break
} else {
    Import-Module ActiveDirectory
}

# Import CSV with SearchBase
Try {
    $SearchBases = Import-CSV "searchbases.txt"
} Catch {
    Write-Output "No Searchbases found"
    $SearchBases = $Null
}

# Getting all on-premises mailbox enabled accounts, filtering system, discovery, federation mailboxes 
# Also filters to get only usermailboxes based on msExchRecipientTypeDetails (if mailbox created correctly...)
# $Accounts =  Get-ADUser -Filter "msExchMailboxGuid -like '*'" | Where {($_.DistinguishedName -notlike "*CN=Microsoft Exchange System Objects*") -xor ($_.DistinguishedName -notlike "CN=DiscoverySearchMailbox {*") -xor ($_.DistinguishedName -notlike "CN=FederatedEmail.*") -xor ($_.DistinguishedName -notlike "CN=Migration.*") -xor ($_.DistinguishedName -notlike "CN=SystemMailbox{*")}
# But another approach is to limit searches based on SearchBase. A loop is required because you can only define one at a time in Get-ADUser.


If ($Null -eq $SearchBases){
    $Accounts = Get-ADUser -Filter 'msExchRecipientTypeDetails -like 1'
} Else {
    ForEach ($SearchBase in $SearchBases) {
    Write-Output $SearchBase
    $Accounts += Get-ADUser -Filter 'msExchangeRecipientTypeDetails -like 1' -SearchBase $SearchBase.SearchBase -SearchScope Subtree
    }
}

# Sorting accounts based on SamAccountName
$Accounts = $Accounts | Sort-Object -Property SamAccountName

#Defining array for Export
$FoundAccounts = @()
$NoPrimarySMTP = @()

# Export current account settings (backup)
#   Current UPN, SamAccountname, PrimaryMail
Write-Output "--"
Write-Output "SamAccountName, UserPrincipalName, PrimarySMTPAddress, DistinguishedName"

ForEach ($Account in $Accounts){
    $Identity = [String]$Account.SamAccountname
    $DistinguishedName = [String]$Account.DistinguishedName

    # Write-Output "Identity is $Identity"
    $PrimaryAddress = Get-ADUser -Identity $Identity -Properties ProxyAddresses | Select-Object -Expand proxyAddresses | Where-Object {$_ -clike "SMTP:*"}
    
    If ($null -ne $PrimaryAddress){
        $PrimaryAddress = $PrimaryAddress.SubString(5)
        $UserPrincipalName = [String]$Account.UserPrincipalName
    
        $CurrentUser = [PSCustomObject] @{
            SamAccountname = $Identity
            UserPrincipalName = $UserPrincipalName
            PrimaryAddress = $PrimaryAddress
            DistinguishedName = $DistinguishedName
        }
        
        Write-Output "$Identity $UserPrincipalName $PrimaryAddress $DistinguishedName"
        $FoundAccounts += $CurrentUser

    } else {

        $UserPrincipalName = [String]$Account.UserPrincipalName
            
        $NoSMTPUser = [PSCustomObject] @{
            SamAccountname = $Identity
            UserPrincipalName = $UserPrincipalName
            DistinguishedName = $DistinguishedName
        }
        
        $NoPrimarySMTP += $NoSMTPUser
    }
   
}

#Get date for export
$LogTime = Get-Date -Format "yyyyMMdd"

#Export to files
$FoundAccounts | Export-CSV -NoTypeInformation -Path $logtime"Mailboxes.txt"
$NoPrimarySMTP | Export-CSV -NoTypeInformation -Path $logtime"NoPrimarySMTP.txt"