# Scripts And Queries
Running list of scripts and queries that assist in review of identity information.


# Active Directory or Azure AD
**LDAPFilter Users & attaching properties to export**<br />
Get-ADUser -LDAPFilter "(<attribut=name*)" -Properties WhenCreated | Export-Csv -Path C:\my\file\path.csv
Get-ADUser -LDAPFilter "(<attribut=name*)" -Properties LastLogonDate | Export-Csv -Path C:\my\file\path.csv

**LDAPFilter Groups**<br />
Get-ADGroup -LDAPFilter "(name=<text name>)" | Export-Csv -Path -Path C:\my\file\path.csv

**Groups without Members**<br />
Get-ADGroup -LDAPFilter "(name=<text name>)" | ?{@(Get-ADGroupMember $_).Length -eq 0} | Export-Csv -Path 'C:\my\file\path.csv'

**All active users**<br />
Get-ADUser -Filter {enabled -eq $true} | Export-Csv -Path C:\my\file\path.csv
  
**Get all computers**<br />
Get-ADComputer -Filter * -Properties LastLogonDate | Export-Csv -Path C:\my\file\path.csv
Get-ADComputer -Filter * -SearchBase "<search base OU full DN>" -Properties * | Select -Property Name | Export-Csv -Path "C:\my\file\path.csv"

**Get Groups & Members**<br />
$groups=Get-ADGroup -Filter 'name -like "<group name>"'

ForEach ($group in $groups){
    $members = Get-ADGroupMember -Identity $group.name
    ForEach ($member in $members){
        Write-output $group.name "," $member.samAccountName >> C:\my\file\path.csv
    }
} 

**Get-ADUser & Attributes - Auto convert LastLogonTimestamp & pwdlastset**<br />
Get-ADUser -Filter * -Properties displayName, name, sAMAccountName, employeeNumber, employeeType, LastLogonTimeStamp, objectGUID, objectSid, primaryGroupID, pwdLastSet, whenCreated, enabled | Select-Object -Property "displayName", "name", "sAMAccountName", "employeeNumber", "employeeType", "objectGUID", "objectSid", "primaryGroupID", "whenCreated", "enabled", @{n="LastLogon";e={[datetime]::FromFileTime($_."LastLogonTimeStamp")}}, @{n="PwdLastSet";e={[datetime]::FromFileTime($_."PwdLastSet")}} | Export-Csv -Path C:\my\file\path.csv

 **FindCertsinAzure** <br />
Import-Module AzureAD

Connect-AzureAD

#Change this to the number of days out you want to look
$daysOut = 30


#Main Script#
$doneID = ""
$countExpiring = 0

$allSAMLApps = Get-AzureADServicePrincipal -All $true | Where-Object {($_.Tags -contains "WindowsAzureActiveDirectoryGalleryApplicationNonPrimaryV1") -or ($_.Tags -contains "WindowsAzureActiveDirectoryCustomSingleSignOnApplication")}

Write-Host "Looking for certs that expire by ((Get-Date).AddDays($daysOut))" -ForegroundColor Green
foreach ($singleApp in $allSAMLApps) {
    
    foreach ($KeyCredential in $singleApp.KeyCredentials) {
        
        if ( $KeyCredential.EndDate -lt (Get-Date).AddDays($daysOut) ) {
            if (($singleApp.ObjectId) -ne $doneID) {
                Write-Host " Name: " ($singleApp.DisplayName) " - Experation: " $KeyCredential.EndDate
                $doneID = ($singleApp.ObjectId)
                $countExpiring = $countExpiring + 1
            }
        }

    }

}

Write-Host "There are $countExpiring certs." -ForegroundColor Green 
  
 # SPLUNK Queries
  
**Find accounts and logged in hosts**<br />
source="WinEventLog:Security" user=<account naming convention>
| stats dc(src) as Number_logged_hosts, count by user
| fields - count
| where Number_logged_hosts > 3
| sort - Number_logged_hosts

**Remote logon to Computers**<br />
index=wineventlog source="WinEventLog:Security" EventCode=4624 Logon_Type=10 ComputerName!=<server name to exclude>
| stats count by user ComputerName

**Where base user accounts are RDPing**<br />
index=wineventlog source="WinEventLog:Security" EventCode=4624 Logon_Type=10 user!=<account to exclude> user!=<account to exclude>user!=<account to exclude>
| stats count by user host
| sort - count

**Where accounts are returning logons (maybe have services configured as their user)**<br />
index=wineventlog source="WinEventLog:Security" EventCode=4624 ComputerName!=<computer info> ComputerName!=v ComputerName!=<computer info> ComputerName!=<computer info> Account_Name!=System Account_Name!=<account info> | stats count by Account_Name, ComputerName, Account_Domain
| sort - count

**Where CyberArk accounts are RDPing**<br />
index=wineventlog source="WinEventLog:Security" EventCode=4624 Logon_Type=10 user=<user name> OR user=<user name>
| stats count by user host
| sort - count

**Where Service Accounts are RDPing to servers**<br />
index=wineventlog source="WinEventLog:Security" EventCode=4624 Logon_Type=10 user=<account name convention> OR user=<account name convention> AND user!=<not account>
| stats count by user host
| sort - count

**New Accounts Last 7 days**<br />
source="WinEventLog:Security" EventCode=4720 SAM_Account_Name!=<exclude account> AND SAM_Account_Name!=<exclude account name> earliest=-7d@d latest=@d-1s 
| dedup SAM_Account_Name
| timechart span=7d count

**Users Logging Into Servers not Computers**<br />
index=wineventlog source="WinEventLog:Security" EventCode=4624 Logon_Type=10 process_name="C:\\Windows\\System32\\winlogon.exe" Security_ID="US\\*" Account_Name!=<exclude accounts> ComputerName!=<exclude computer> ComputerName!=<exclude computer>
| eval logging_in_user=mvindex(Account_Name,1)
| table logging_in_user ComputerName
| dedup logging_in_user ComputerName
