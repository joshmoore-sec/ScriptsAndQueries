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
```
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
```
**Create Accounts**<br />
```
#Enter a path to your import CSV file
$ADUsers = Import-csv C:\my\file\path.csv

foreach ($User in $ADUsers)
{

       $Username    = $User.username
       $Password    = $User.password
       $Firstname   = $User.firstname
       $Lastname    = $User.lastname
       $OU           = $User.ou

       #Check if the user account already exists in AD
       if (Get-ADUser -F {SamAccountName -eq $Username})
       {
               #If user does exist, output a warning message
               Write-Warning "A user account $Username has already exist in Active Directory."
       }
       else
       {
        #If a user does not exist then create a new user account
          
        #Account will be created in the OU listed in the $OU variable in the CSV file; don’t forget to change the domain name in the"-UserPrincipalName" variable
            New-ADUser -SamAccountName $Username -UserPrincipalName "$Username@<domain.com>" -Name "$Firstname $Lastname" -GivenName $Firstname -Surname $Lastname -Enabled $True -ChangePasswordAtLogon $False -DisplayName "$Lastname, $Firstname" -Path $OU -AccountPassword (convertto-securestring $Password -AsPlainText -Force)

       }
}
```
<br /> 
  
**Get AD Group Members** <br />
```
$Members= Get-ADGroupMember -Identity "group name"
$Members | Get-ADUser -Properties name, UserPrincipalName | Select-Object name, UserPrincipalName

**ADGroups For Loop** (needs fix to the for each, duplicate entries) <br />
$myGroups =@('group name', 'group name', 'group name', 
'group name', 'group name', 'group name', 
'group name', ''group name', 'group name')

foreach($groupName in $myGroups)
{
$Members= Get-ADGroupMember -Identity $groupName
    foreach ($individual in $Members)
    {
    $myOutput += $Members | Get-ADUser -Properties name, UserPrincipalName | Select-Object name, UserPrincipalName, @{n='Group';e={$groupName}}
    $myOutput | Export-CSV 'C:\my\file\path.csv'
    }
    
}
```

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
  
 # CyberArk API Account & Safe Management
 **API Information**
* https://github.com/cyberark/apv-api-scripts
* 'CyberArk PVWA'/passwordvault/swagger/ui
* https://cybr.rocks/restapi 
  
 **Safe Creation** <br />
 .\Safe-Management.ps1 -PVWAURL "pvwa URL" -Add -FilePath "C:\Temp\SafeOnboard.csv"
  
 **Add Members** <br />
  .\Safe-Management.ps1 -PVWAURL "'pvwa URL" -Add -FilePath "C:\Temp\SafeMembers.csv"
  
  **Onboard Accounts**<br />
  .\Accounts_Onboard_Utility.ps1 -PVWAURL "'pvwa URL'" -CsvPath .\Test_AccountOnboard.csv -Create -NoSafeCreation
 
