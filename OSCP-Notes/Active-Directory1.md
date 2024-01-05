## Active Directory
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
