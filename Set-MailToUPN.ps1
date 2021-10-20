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

# check allowed UPN suffix, commandline multivalued
$UPNSuffixes = Import-CSV -Path "UPNSuffix.txt"
Write-Output "Checking UPN Suffixes"
ForEach ($UPNSuffix in $UPNSuffixes) {
    Write-Output $UPNSuffix
}



# Import CSV with accounts, column SamAccountname
$Accounts = Import-CSV -Path "Accounts.txt"

# Export current account settings (backup)
#   Current UPN, SamAccountname, PrimaryMail
ForEach ($Account in $Accounts){
    $Identity = [String]$Account.SamAccountname
    Write-Output "Identity is $Identity"
    Get-ADUser -Identity $Identity -Properties 'ProxyAddresses'


# create export CSV append
}


# Start Transcript if requested
If ($TranscriptOn -eq $true) {
    # Defining logtime variable to be used in logging/default output folder
    $LogTime = Get-Date -Format "yyyyMMdd_hhmm_ss"

    # Initialize logging
    $TranscriptFile = "SetMailToUPN_"+$LogTime+".txt"
    Start-Transcript -Path $TranscriptFile
}
# loop accounts

# Get account primary mailadres
ForEach ($Account in $Accounts){
    # Does it have a mailbox? Get-ADUser -LDAPFilter "(msExchMailboxGuid=*)"
    $ModifyUser = Get-ADUser -Identity $Account -Properties 'ProxyAddresses'
    [String]$PrimaryAddress = $ModifyUser.'ProxyAddresses' -clike 'SMTP:*'

    # check on domain suffix
    # if okay, then set value UPN = PrimaryMail
    # if not okay, error handling  
    ForEach ($UPNSuffix in $UPNSuffixes) {
        $Check = $UPNSuffix -clike $PrimaryAddress
        Write-Output "$PrimaryAddress : $UPNSuffix is $Check"
    }

    $Okay = Set-ADUser -Identity $Account -UserPrincipalName $PrimaryAddress
    Write-Output "$Account has now UPN $PrimaryAddress"
}

# export CSV 
#  append UPN, PrimaryMail, SamAccountname of processed account

# end loop

# Clean up 
Remove-Module ActiveDirectory
Stop-Transcript