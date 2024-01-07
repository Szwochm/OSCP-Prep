## Active Directory Basics

xfreerdp /u:stephanie /d:corp.com /v:192.168.233.70

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


