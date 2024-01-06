function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}

#Usage: more details in the master file on what these output
#1 powershell -ep bypass
#1.5 Import-Module .\function.ps1

#2 LDAPSearch -LDAPQuery "(samAccountType=805306368)"
#3 LDAPSearch -LDAPQuery "(objectclass=group)"
# 3.5 $usr = LDAPSearch -LDAPQuery "(&(objectClass=user)(cn=jen))"
# 3.5 $usr.properties
#OR 3.6 (LDAPSearch -LDAPQuery "(&(objectClass=user)(cn=jen))").properties

#4 foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
#4 >> $group.properties | select {$_.cn}, {$_.member}
#4 >> }

#5 $sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
#5.5 $sales.properties.member

#6 dig deeper after finding out dev depart is part of sales $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"
