# Import file with original SamAccountName & UPN
# Change UPN back to original value

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
$Accounts = Import-CSV -Path "Restored.txt"


Write-Output "Changing UPN to Primary SMTP"

$RestoredAccounts = @()

ForEach ($Account in $Accounts){
    $Identity = [String]$Account.SamAccountname
    $DistinguishedName = [String]$Account.DistinguishedName
    $PrimaryAddress = Get-ADUser -Identity $Identity -Properties ProxyAddresses | Select-Object -Expand proxyAddresses | Where-Object {$_ -clike "SMTP:*"}
    $PrimaryAddress = $PrimaryAddress.SubString(5)

    If ($null -ne $PrimaryAddress){
        
        $UserPrincipalName = [String]$Account.UserPrincipalName

        #Actually changing UPN
        Try {
            Write-Output "Reverting $Identity UPN to $UserPrincipalName"
            Set-ADUser -Identity $Identity -UserPrincipalName $UserPrincipalName        
        } Catch {
            Write-Output "Error with $Identity and $UserPrincipalName "
        }

        # Registering what has been changed
        $UserPrincipalName = (Get-ADUser -Identity $Identity).UserPrincipalName
        $RestoredUser = [PSCustomObject] @{
            SamAccountname = $Identity
            UserPrincipalName = $UserPrincipalName
            PrimaryAddress = $PrimaryAddress
            DistinguishedName = $DistinguishedName
        }
        
        #Write-Output "$Identity $UserPrincipalName $PrimaryAddress $DistinguishedName"
        $RestoredAccounts += $RestoredUser

    } else {
        #If there is no Primary SMTP found
        Write-Output "Error $Identity : No Primary SMTP found"
    }
   
}


#Get date for export
$LogTime = Get-Date -Format "yyyyMMdd"

#Export to files
$RestoredAccounts | Export-CSV -NoTypeInformation -Path $logtime"RestoredAccounts.txt"


# Clean up 
Remove-Module ActiveDirectory

If ($TranscriptOn -eq $true) {
    Stop-Transcript
}