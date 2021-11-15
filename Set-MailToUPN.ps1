# 
# Required imports Mailboxes.txt with SamAccountName as minimal input column
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
# Write-Output "SamAccountName, UserPrincipalName, PrimarySMTPAddress"

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
        
        #Write-Output "$Identity $UserPrincipalName $PrimaryAddress $DistinguishedName"
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

Write-Output "Changing UPN to Primary SMTP"

$ChangedAccounts = @()

ForEach ($Account in $Accounts){
    $Identity = [String]$Account.SamAccountname
    $DistinguishedName = [String]$Account.DistinguishedName
    $PrimaryAddress = Get-ADUser -Identity $Identity -Properties ProxyAddresses | Select-Object -Expand proxyAddresses | Where-Object {$_ -clike "SMTP:*"}
    
    If ($null -ne $PrimaryAddress){
        $PrimaryAddress = $PrimaryAddress.SubString(5)
        $UserPrincipalName = [String]$Account.UserPrincipalName
        
        #Actually changing UPN
        Try {
            Write-Output "Changing $Identity UPN to $PrimaryAddress"
            Set-ADUser -Identity $Identity -UserPrincipalName $PrimaryAddress           
        } Catch {
            Write-Output "Error with $Identity and $PrimaryAddress "
        }

        # Registering what has been changed
        $UserPrincipalName = (Get-ADUser -Identity $Identity).UserPrincipalName
        $ChangedUser = [PSCustomObject] @{
            SamAccountname = $Identity
            UserPrincipalName = $UserPrincipalName
            PrimaryAddress = $PrimaryAddress
            DistinguishedName = $DistinguishedName
        }
        
        #Write-Output "$Identity $UserPrincipalName $PrimaryAddress $DistinguishedName"
        $ChangedAccounts += $ChangedUser

    } else {
        #If there is no Primary SMTP found
        Write-Output "Error $Identity : No Primary SMTP found"
    }
   
}


#Get date for export
$LogTime = Get-Date -Format "yyyyMMdd"

#Export to files
$CurrentAccounts | Export-CSV -NoTypeInformation -Path $logtime"CurrentAccounts.txt"
$CurrentNoPrimarySMTP | Export-CSV -NoTypeInformation -Path $logtime"CurrentNoPrimarySMTP.txt"
$ChangedAccounts | Export-CSV -NoTypeInformation -Path $logtime"ChangedAccounts.txt"


# Clean up 
Remove-Module ActiveDirectory

If ($TranscriptOn -eq $true) {
    Stop-Transcript
}