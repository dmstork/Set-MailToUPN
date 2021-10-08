
Param(
    [switch]$TranscriptOn
)


# check allowed UPN suffix, commandline multivalued
$UPNSuffixes = Import-CSV -Path "UPSuffix.txt"

# Import CSV with accounts, column SamAccountname
# Export current account settings (backup)
#   Current UPN, SamAccountname, PrimaryMail

# create export CSV append

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
# check on domain suffix
#   if okay, then set value UPN = PrimaryMail
#   if not okay, error handling
# export CSV 
#  append UPN, PrimaryMail, SamAccountname of processed account

# end loop
