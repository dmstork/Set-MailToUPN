
##Nope
check allowed UPN suffix, commandline multivalued
Import CSV with accounts, column SamAccountname
Export current account settings (backup)
  Current UPN, SamAccountname, PrimaryMail

create export CSV append

loop accounts

Get account primary mailadres
 check on domain suffix
  if okay, then set value UPN = PrimaryMail
   if not okay, error handling
 export CSV 
  append UPN, PrimaryMail, SamAccountname of processed account

end loop

[string]$primaryAddress = $testUser.'ProxyAddresses' -clike 'SMTP:*'
$testUser = Get-AdUser -Identity 'Meel' -Properties 'ProxyAddresses'
[string]$primaryAddress = $testUser.'ProxyAddresses' -clike 'SMTP:*'
$primaryAddress