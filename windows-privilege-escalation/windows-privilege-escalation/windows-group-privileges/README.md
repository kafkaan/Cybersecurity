# Windows Group Privileges

## <mark style="color:red;">Windows Built-in Groups</mark>

***

Windows possède des **groupes intégrés** donnant des privilèges spéciaux (ex. Domain Admins, Backup Operators).\
En audit ou pentest, trouver un compte dans un de ces groupes permet souvent d’**escalader ses droits**.\
Il faut **vérifier régulièrement** les membres pour supprimer les accès inutiles et appliquer le **principe du moindre privilège**.

[Here](https://ss64.com/nt/syntax-security_groups.html) is a listing of all built-in Windows groups along with a detailed description of each. This [page](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory) has a detailed listing of privileged accounts and groups in Active Directory

| [Backup Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-backupoperators)            | [Event Log Readers](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-eventlogreaders) | [DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-dnsadmins)              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Hyper-V Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-hypervadministrators) | [Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-printoperators)    | [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) |

***
