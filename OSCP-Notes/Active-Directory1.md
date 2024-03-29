## Active Directory Basics

xfreerdp /u:stephanie /d:corp.com /v:192.168.233.75

net user /domain

net user jeffadmin /domain

net group /domain


**Default groups**
*Cloneable Domain Controllers
*Debug
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Schema Admins

Enumerating a custom group is a good start

net group "Sales Department" /domain

## Enumerating Active Directory using PowerShell and .NET Classes

Note: LDAP is not exclusive to AD. Other services use it as well.

Note: Powershell cmdlets like Get-AdUser are only installed by default on DC

#### AD enumeration relies on LDAP. When a domain machine searches for an object, like a printer, or when we query user or group objects, LDAP is used as the communication channel for the query.

We will use AD Service Interfaces as an LDAP provider

we need a specific LDAP ADsPath in order to communicate with the AD service
LDAP://HostName[:PortNumber][/DistinguishedName] where host can be an computer name, domain name or ip. Port is optional.

A distinguished name has to do with AD naming convention so for example
CN=Stephanie,CN=Users,DC=corp,DC=com is read RIGHT -> LEFT
com.corp.Users.Stephanie

For example we can get PDC using getPDC script which can return would be DC1.corp.com, thats the distinguished name

We can query any DC, but the Primary DC is the best.

Powershell -- Invoke Domain Class and GetCurrentDomain Methods
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

When scripting in powershell we must use bypass

powershell -ep bypass


We can also use ADSI to get DN for the domain using a domain object

([adsi]'').distinguishedName

Net-frame has alot of details so added a master file explaining the building of the script in the OSCP Scripts folder (https://github.com/Szwochm/OSCP-Prep/new/main/Scripts)


### AD Enum w/ PowerView

Import-Module .\PowerView.ps1


Get-NetDomain

List all users in domain and all of their properties
Get-NetUser

List the cn property of every user in the domain
Get-NetUser | select cn

List all properties of fred
Get-NetUser | Where-Object { $_.cn -eq 'fred' }

List the CN (common name), last time password was set, and last login for every user. (A user that hasn't logged in since the a passwordp policy change could still have a weak password)
Get-NetUser | select cn,pwdlastset,lastlogon

List every group by its Common Name
Get-NetGroup | select cn

Get-NetGroup "Sales Department" | select member

### More Powerview (21.3.1 and further)

List every computer object
Get-NetComputer

List all computers by OS, DNS name
Get-NetComputer | select operatingsystem,dnshostname

Get a specific computers details
Get-NetComputer | Where-Object { $_.cn -eq 'files04' }

### Getting an Overview - Permissions and Logged on Users


.

For the exam we want Domain Admin privs but in real life you may want to secure some lateral accounts first so you don't get locked out

(PowerView) -- where does this user have local admin access on the domain?
Find-LocalAdminAccess

Who's logged into the machines. NetSession uses Window's NetWkstaUserEnum and NetSessionEnum APIs
Get-NetSession -ComputerName files04

Who is logged into the machines show errors
Get-NetSession -ComputerName files04 -Verbose

Note: Not sure if the below block is helpful 
The permissions required to enumerate sessions with NetSessionEnum are defined in the SrvsvcSessionInfo registry key, which is located in the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity hive.

Show permissions for registrykey
(powershell)
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl

if Get-NetSession doesn't work you can try using the below, find the oldest OS, run it on that client
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion


#### Introducing PSLoggedOn 21.3.2
PsLoggedOn will enumerate the registry keys under HKEY_USERS to retrieve the security identifiers (SID) of logged-in users and convert the SIDs to usernames. PsLoggedOn will also use the NetSessionEnum API to see who is logged on to the computer via resource shares.

One limitation, however, is that PsLoggedOn relies on the Remote Registry service in order to scan the associated key. The Remote Registry service has not been enabled by default on Windows workstations since Windows 8, but system administrators may enable it for various administrative tasks, for backwards compatibility, or for installing monitoring/deployment tools, scripts, agents, etc.

.\PsLoggedon.exe <hostname or \\cn>
.\PsLoggedon.exe \\files04

take note of who's logged on every machine

### Enumeration Through Service Principal Names (service accounts) 21.3.3

In Windows, if a user launches an app, it runs in their context, however

Services can use predefined accounts such as 
LocalSystem, LocalService, and NetworkService

Group managed service accounts were implemented in Windows Server 2012, anything before that uses basic service accounts

Instead of doing an NMAP port scan, We can obtain the IP address and port number of applications running on servers integrated with AD by simply enumerating all SPNs in the domain. (SPNS map services to service accounts in AD)

(Built-in) get SPN of an account, iis_service in this case. Can be any user
setspn -L iis_service

(Powerview) Enumerate every account, and get their related SPNS
Get-NetUser -SPN | select samaccountname,serviceprincipalname

which returns
iis_service    {HTTP/web04.corp.com, HTTP/web04, HTTP/web04.corp.com:80}

resolve the name
nslookup.exe web04.corp.com

### Enumerating Object Permissions 21.3.4

an object in AD may have a set of permissions applied to it with multiple Access Control Entries (ACE).1 These ACEs make up the Access Control List (ACL).2 Each ACE defines whether access to the specific object is allowed or denied.

When a user tries to use a resource they send their access token to the target object. Target object then checks ACL (which is a list of permissions)

List of interesting permissions to review

GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object (ACE's are Access Control Entries and make up the ACL)
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group

PowerView -- enumerate ACEs with PowerView
Get-ObjectAcl -Identity stephanie

PowerView -- convert SID to english where the SID below is an ObjectSID
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104

Same as above but this time we are applying it to a SecurityIdentifier 
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553

which returns CORP\RAS and IAS Servers indicating RAS and IAS Servers group has ReadProperty access rights to our user. While this is a common configuration in AD and likely won't give us an attack vector, we have used the example to make sense of the information we have obtained.

Reminder: The highest access permission we can have on an object is GenericAll.

PowerView -- check if any user in Management Department has GenericAll Permissions
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

Convert a bunch of SIDs to english
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName

Using genericall permission, add your self to a group
net group "Management Department" stephanie /add /domain

verify it worked
Get-NetGroup "Management Department" | select member

remove ourselfs from group
net group "Management Department" stephanie /del /domain

### Enumerating Domain Shares 21.3.5

Note: the Find-DomainShare tool was acting funky for me. Had to run it a couple of times

Find all domain shares
Find-DomainShare

Find all domain shares that we can access
Find-DomainShare -CheckShareAccess

look inside share -- note corp.com is a directory we just literally took \\<computername>\<name> from the last commands output

ls \\dc1.corp.com\sysvol\corp.com\

decrypt found AES-256 hash of Group Policy Preferences hash
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"

store found passwords for later, try to figure out password policy from found passwords

Document every thing you find, but don't jump the gun


### Active Directory - Automated Enumeration (BloodHound, sharphound)

BloodHound = data presenter
SharpHound = collect data using the manual methods above

Import-Module .\Sharphound.ps1

Info on how to use sharphound
Get-Help Invoke-BloodHound

Gather all data, sent to zip json file called corp audit on desktop
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"

Looping isn't covered in OSCP but helps find changes (as in it catches the changes, it won't tell you "HEY THIS IS A CHANGE" as far as I understand) during the scan

### Analysing Data using BloodHound

sudo neo4j start

navigate to http:\\localhost:7474\

log-in

in kali run bloodhound

login-in

upload data aquired by sharphound

If using Shortest Path from owned principals dont forget to mark the users and devices you have access to.


### Capstone

Change a user's password that you have generic write over
net user someuser Password123! /domain
