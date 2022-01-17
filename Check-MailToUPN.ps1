# Simple script written by Dave Stork 
# Mail: dmstork at stalpaert.nl
# Twitter: @dmstork
# 
# Provided as is, use at own risk.
#
# Checks AD user accounts with mailbox whether their AD UPN corresponds with their primary SMTP
# The AD UPN = Primary SMTP is the recommended configuration as this is assumed by Microsoft 365 
# Services and apps and increases the user experience positivly.
#
# .KNOWNISSUES
# Option to search only specific OU's is still in development and might not work


Param(
    # Mandatory. Specifies a filepath to CSV file with accounts to be restored to original state.
    # You can use the OriginalStateAccounts from the Set-MailToUPN Script.
    [Parameter(Mandatory=$False,
             ValueFromPipeline=$true,
             ValueFromPipelineByPropertyName=$true,
             HelpMessage="Path CSV file with accounts to be processed")]
      [ValidateNotNullOrEmpty()]
      [string]$SearchBaseFile
)

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
    $SearchBases = Import-CSV $SearchBaseFile
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
$MismatchAccounts = @()
$CorrectAccounts = @()
$NoPrimarySMTP = @()

ForEach ($Account in $Accounts){
    $Identity = [String]$Account.SamAccountname
    $DistinguishedName = [String]$Account.DistinguishedName
    $UserPrincipalName = [String]$Account.UserPrincipalName

    # Write-Output "Identity is $Identity"
    $PrimaryAddress = Get-ADUser -Identity $Identity -Properties ProxyAddresses | Select-Object -Expand proxyAddresses | Where-Object {$_ -clike "SMTP:*"}
    
    # If the PrimaryAddress value is not emtpy
    If ($null -ne $PrimaryAddress){
        $PrimaryAddress = $PrimaryAddress.SubString(5)
        
        # Temporary store attributes of current processed account
        $CurrentUser = [PSCustomObject] @{
            SamAccountname = $Identity
            UserPrincipalName = $UserPrincipalName
            PrimaryAddress = $PrimaryAddress
            DistinguishedName = $DistinguishedName
        }
        
        # If the PrimarySMTP corresponds with UserPrincipalName, it should be stored in CorrectAccounts
        If ($PrimaryAddress -eq $UserPrincipalName){
            $CorrectAccounts += $CurrentUser
        # If the PrimarySMTP does NOT correspond with UserPrincipalName, it should be store in MismatchAccounts
        } elseif ($PrimaryAddress -ne $UserPrincipalName){
            $MismatchAccounts += $CurrentUser
        } 
       

    } else {
        # The PrimarSMTP attribute is empty, so possibly no PrimarySMTP or other issue and stored in NoSMTPUser
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
$LogTime = Get-Date -Format "yyyyMMdd_hhmm"

#Export to files
$MismatchAccounts | Export-CSV -NoTypeInformation -Path $Logtime"_MismatchAccounts.txt"
$CorrectAccounts | Export-CSV -NoTypeInformation -Path $LogTime"_CorrectAccounts.txt" 
$NoPrimarySMTP | Export-CSV -NoTypeInformation -Path $Logtime"_NoPrimarySMTP.txt"