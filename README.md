
# Set-MailToUPN

Setting UPN based on primary SMTP, using CSV with SamAccountName list of users to be changed
CSV import required.

# Get-MailToUPN

Exporting every mailbox user (based on recipient type detail) to CSV. Additional manual filtering is probably required

# Restore-MailToUPN

Restoring changed UPN based on original values exported by Set-MailToUPN. Does require a CSV input.
