# Simple script written by Dave Stork 
# Mail: dmstork at stalpaert.nl
# Twitter: @dmstork
# 
# Provided as is, use at own risk.
#
# Imports (OriginalStateAccounts) CSV file with SamAccountName as minimal input column.
# This CSV should have the original SamAccountName & UPN combination.
# Changes UPN back to original value
# Requires the AD PowerShell module
# 


Param(
    # Turns on transcript if selected, optional
    [switch]$TranscriptOn,
    # Mandatory. Specifies a filepath to CSV file with accounts to be restored to original state.
    # You can use the OriginalStateAccounts from the Set-MailToUPN Script.
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

# Import CSV file with orignal values
# Could be the OriginalStateAccounts CSV files created by Set-MailToUPN.ps1
Try {
    $Accounts = Import-CSV -Path $CSVFile -ErrorAction Continue
} Catch {
    Write-Error "Failed to import CSV File" -ErrorAction Stop
}

Write-Output "Changing UPN to Primary SMTP"

#Defining array to store what has been changed (yes, should be the same as CSV File)
$RestoredAccounts = @()

# Loop with the actual restoration of original value according to CSV
ForEach ($Account in $Accounts){
    
    # Defining the account variables from CSV file
    $Identity = [String]$Account.SamAccountname
    $DistinguishedName = [String]$Account.DistinguishedName   
    $UserPrincipalName = [String]$Account.UserPrincipalName

    #Actually changing UPN
    Try {
            Write-Output "Reverting $Identity UPN to $UserPrincipalName"
            Set-ADUser -Identity $Identity -UserPrincipalName $UserPrincipalName        
    } Catch {
            Write-Output "Error with $Identity and $UserPrincipalName "
    }

    # Registering what has been changed in object
    $UserPrincipalName = (Get-ADUser -Identity $Identity).UserPrincipalName
    $RestoredUser = [PSCustomObject] @{
        SamAccountname = $Identity
        UserPrincipalName = $UserPrincipalName
        PrimaryAddress = $PrimaryAddress
        DistinguishedName = $DistinguishedName
    }
        
    # Adding changed accounts to array
    $RestoredAccounts += $RestoredUser
}


#Get date for export
$LogTime = Get-Date -Format "yyyyMMdd_hhmm"

#Export the performed action to a CSV file
$RestoredAccounts | Export-CSV -NoTypeInformation -Path $logtime"_RestoredAccounts.txt"


# Clean up PS Modules
Remove-Module ActiveDirectory

# Turning of Transcript
If ($TranscriptOn -eq $true) {
    Stop-Transcript
}