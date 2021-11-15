# 
# Required imports UPNSuffix.txt and Accounts.txt
# 

Param(
    [switch]$TranscriptOn
)

# User ActiveDirectory
$Check = Get-Command -Module ActiveDirectory
If ($Null -eq $Check){
    Write-Output "Error: Active Directory PowerShell module is not installed on this machine. Stopping."
    Break
} else {
    Import-Module ActiveDirectory
}

# Start Transcript if requested
If ($TranscriptOn -eq $true) {
    # Defining logtime variable to be used in logging/default output folder
    $LogTime = Get-Date -Format "yyyyMMdd_hhmm_ss"

    # Initialize logging
    $TranscriptFile = "SetMailToUPN_"+$LogTime+".txt"
    Start-Transcript -Path $TranscriptFile
}



# Import CSV with SamAccountName, UserPrincipalName and their primary SMTP. 
# Information gathered by Get-MailToUPN.ps1 and manually verified. There are no checks whether SMTP is correct and UPN suffixes exist
$Accounts = Import-CSV -Path "Mailboxes.txt"

#Defining array for Export
$CurrentAccounts = @()
$CurrentNoPrimarySMTP = @()

# Export current account settings (backup)
#   Current UPN, SamAccountname, PrimaryMail
Write-Output "Current attribute values exported"
Write-Output "SamAccountName, UserPrincipalName, PrimarySMTPAddress"

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
        $CurrentAccounts += $CurrentUser

    } else {

        $UserPrincipalName = [String]$Account.UserPrincipalName
            
        $NoSMTPUser = [PSCustomObject] @{
            SamAccountname = $Identity
            UserPrincipalName = $UserPrincipalName
            DistinguishedName = $DistinguishedName
        }
        
        $CurrentNoPrimarySMTP += $NoSMTPUser
    }
   
}

#Get date for export
$LogTime = Get-Date -Format "yyyyMMdd"

#Export to files
$CurrentAccounts | Export-CSV -NoTypeInformation -Path $logtime"CurrentAccounts.txt"
$CurrentNoPrimarySMTP | Export-CSV -NoTypeInformation -Path $logtime"CurrentNoPrimarySMTP.txt"



# Clean up 
Remove-Module ActiveDirectory

If ($TranscriptOn -eq $true) {
    Stop-Transcript
}