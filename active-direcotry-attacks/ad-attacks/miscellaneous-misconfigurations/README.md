# Miscellaneous Misconfigurations

## <mark style="color:red;">Miscellaneous Misconfigurations</mark>

***

### <mark style="color:blue;">Sniffing LDAP Credentials</mark>

Many applications and printers store LDAP credentials in their web admin console to connect to the domain. These consoles are often left with weak or default passwords. Sometimes, these credentials can be viewed in cleartext. Other times, the application has a `test connection` function that we can use to gather credentials by changing the LDAP IP address to that of our attack host and setting up a `netcat` listener on LDAP port 389. When the device attempts to test the LDAP connection, it will send the credentials to our machine, often in cleartext. Accounts used for LDAP connections are often privileged, but if not, this could serve as an initial foothold in the domain.&#x20;

{% hint style="warning" %}
Other times, a full LDAP server is required to pull off this attack, as detailed in this [post](https://grimhacker.com/2018/03/09/just-a-printer/).
{% endhint %}

***

### <mark style="color:blue;">Password in Description Field</mark>

Sensitive information such as account passwords are sometimes found in the user account `Description` or `Notes` fields and can be quickly enumerated using PowerView. For large domains, it is helpful to export this data to a CSV file to review offline.

<mark style="color:green;">**Finding Passwords in the Description Field using Get-Domain User**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

samaccountname description
-------------- -----------
administrator  Built-in account for administering the computer/domain
guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account
ldap.agent     *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
```
{% endcode %}

***

### <mark style="color:blue;">PASSWD\_NOTREQD Field</mark>

Il est possible de tomber sur des comptes de domaine avec le champ **passwd\_notreqd** défini dans l’attribut **userAccountControl**.\
Si ce champ est activé, l’utilisateur n’est pas soumis à la politique actuelle de longueur de mot de passe, ce qui signifie qu’il pourrait avoir un mot de passe plus court ou même aucun mot de passe (si les mots de passe vides sont autorisés dans le domaine).

Un mot de passe peut être défini comme vide intentionnellement (parfois, les administrateurs ne veulent pas être appelés en dehors des heures de travail pour réinitialiser les mots de passe des utilisateurs) ou accidentellement, en appuyant sur **Entrée** avant de saisir un mot de passe lors d’un changement via la ligne de commande.

Ce n’est pas parce que ce drapeau est activé sur un compte qu’aucun mot de passe n’est défini, mais plutôt qu’il **n’est pas obligatoire**.

Il existe plusieurs raisons pour lesquelles ce drapeau peut être défini sur un compte utilisateur, notamment le fait qu’un produit tiers l’ait activé lors de l’installation et ne l’ait jamais supprimé après.

Il est utile d’**énumérer** les comptes ayant ce drapeau activé et de les tester pour voir si aucun mot de passe n’est requis (j’ai vu cela plusieurs fois lors d’audits).

Enfin, il est important d’**inclure cette information dans le rapport client** si l’objectif de l’évaluation est d’être aussi **exhaustif que possible**.

<mark style="color:green;">**Checking for PASSWD\_NOTREQD Setting using Get-DomainUser**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

samaccountname                                                         useraccountcontrol
--------------                                                         ------------------
guest                ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
mlowe                                PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
ehamilton                            PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
$725000-9jb50uejje9f                       ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT
nagiosagent                                                PASSWD_NOTREQD, NORMAL_ACCOUNT
```
{% endcode %}

***
