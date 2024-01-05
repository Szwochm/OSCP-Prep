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

We can query any DC, but the Primary DC is the best.

Powershell -- Invoke Domain Class and GetCurrentDomain Methods
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

When scripting in powershell we must use bypass
powershell -ep bypass
