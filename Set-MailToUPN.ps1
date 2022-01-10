# Simple script written by Dave Stork 
# Mail: dmstork at stalpaert.nl
# Twitter: @dmstork
# 
# Provided as is, use at own risk.
#
# Imports CSV file with SamAccountName as minimal input column.
# Changes current AD UPN to the primary SMTP address found in AD.
# Saves original values before changing (can be used with Restore-MailToUPN.ps1)
# Requires the AD PowerShell module
# 

# Definition of possible parameters and switches
# TranscriptOn will create a transcript file in the running folder
# InputFile is the CSV with accounts that have to be changed.
Param(
    [switch]$TranscriptOn,
    # Specifies a filepath to CSV file with accounts to be changed. Mandatory
    [Parameter(Mandatory=$True,
              ValueFromPipeline=$true,
              ValueFromPipelineByPropertyName=$true,
              HelpMessage="Path CSV file with accounts to be processed")]
              [ValidateNotNullOrEmpty()]
              [string]$CSVFile
)

# Check wether ActiveDirectory PowerShell module is installed and Imports module ifso
$Check = Get-Command -Module ActiveDirectory
If ($Null -eq $Check){
    Write-Output "Error: Active Directory PowerShell module is not installed on this machine. Stopping."
    Break
} else {
    Import-Module ActiveDirectory
}

# Start Transcript if requested via switch
If ($TranscriptOn -eq $true) {
    # Defining logtime variable to be used in logging/default output folder
    $LogTime = Get-Date -Format "yyyyMMdd_hhmm_ss"

    # Initialize logging
    $TranscriptFile = "SetMailToUPN_"+$LogTime+".txt"
    Start-Transcript -Path $TranscriptFile
}



# Import CSV with SamAccountName, UserPrincipalName and PrimarySMTPAddress
# Information can be gathered by Get-MailToUPN.ps1 and manually verified. 
# There are no checks whether SMTP is correct and UPN suffixes exist
Try {
    $Accounts = Import-CSV -Path $CSVFile -ErrorAction Continue
} Catch {
    Write-Error "Failed to import CSV File" -ErrorAction Stop
}

# legacy import
# $Accounts = Import-CSV -Path "Mailboxes.txt"

#Defining array for Export
$CurrentAccounts = @()
$CurrentNoPrimarySMTP = @()

# Export current account settings (backup)
#   Current UPN, SamAccountname, PrimaryMail

Write-Output "Current attribute values exported"
# Write-Output "SamAccountName, UserPrincipalName, PrimarySMTPAddress"

#Loop for handling each row ie account
ForEach ($Account in $Accounts){
    $Identity = [String]$Account.SamAccountname
    $DistinguishedName = [String]$Account.DistinguishedName

    # Determining the Primary SMTP address from multiple values. It should start with capitol SMTP: and then the address.
    $PrimaryAddress = Get-ADUser -Identity $Identity -Properties ProxyAddresses | Select-Object -Expand proxyAddresses | Where-Object {$_ -clike "SMTP:*"}
    
    # Check whether there is a PrimarySMTP address present.
    # If this is the case, the current values are stored in array for later export
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
        # When no Primary SMTP address is found, the values are stored in another array for later export
        $UserPrincipalName = [String]$Account.UserPrincipalName
            
        $NoSMTPUser = [PSCustomObject] @{
            SamAccountname = $Identity
            UserPrincipalName = $UserPrincipalName
            DistinguishedName = $DistinguishedName
        }
        
        $CurrentNoPrimarySMTP += $NoSMTPUser
    }
   
}

# Now we are going to actually change the UPN of the accounts that have a Primary SMTP
Write-Output "Changing UPN to Primary SMTP"

$ChangedAccounts = @()

ForEach ($Account in $Accounts){
    $Identity = [String]$Account.SamAccountname
    $DistinguishedName = [String]$Account.DistinguishedName
    
    # Determining the Primary SMTP address from multiple values. It should start with capitol SMTP: and then the address.
    $PrimaryAddress = Get-ADUser -Identity $Identity -Properties ProxyAddresses | Select-Object -Expand proxyAddresses | Where-Object {$_ -clike "SMTP:*"}
    
    # Check to see if there is a Primary SMTP present
    If ($null -ne $PrimaryAddress){
        
        #Primary SMTP is created by omitting the first 5 characters (SMTP:)
        $PrimaryAddress = $PrimaryAddress.SubString(5)
        $UserPrincipalName = [String]$Account.UserPrincipalName
        
        #Actually changing UPN
        Try {
            Write-Output "Changing $Identity UPN to $PrimaryAddress"
            Set-ADUser -Identity $Identity -UserPrincipalName $PrimaryAddress           
        } Catch {
            Write-Output "Error with $Identity and $PrimaryAddress "
        }

        # Registering what has been changed in this account, saved in array
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
$LogTime = Get-Date -Format "yyyyMMdd_hhmm"

#Exporting all arrays to CSV files
$CurrentAccounts | Export-CSV -NoTypeInformation -Path $logtime"_OriginalStateAccounts.txt"
$CurrentNoPrimarySMTP | Export-CSV -NoTypeInformation -Path $logtime"_CurrentNoPrimarySMTP.txt"
$ChangedAccounts | Export-CSV -NoTypeInformation -Path $logtime"_ChangedAccounts.txt"


# Clean up PS Modules
Remove-Module ActiveDirectory

# Turn of Transcript
If ($TranscriptOn -eq $true) {
    Stop-Transcript
}