# Miscellaneous Misconfigurations

## <mark style="color:red;">Miscellaneous Misconfigurations</mark>

***

### <mark style="color:blue;">Sniffing LDAP Credentials</mark>

Beaucoup d’applications et d’imprimantes stockent des identifiants LDAP dans leur console d’administration web pour se connecter au domaine.

* Ces consoles sont fréquemment protégées par des mots de passe faibles ou laissés par défaut, ce qui les rend vulnérables.&#x20;
* Dans certains cas, les identifiants LDAP sont directement visibles en clair dans l’interface, tandis que dans d’autres, une fonction de "Test de connexion" LDAP permet de détourner l’authentification en redirigeant l’adresse IP vers une machine attaquante, exposant ainsi les identifiants envoyés lors du test.

{% hint style="warning" %}
Other times, a full LDAP server is required to pull off this attack, as detailed in this [post](https://grimhacker.com/2018/03/09/just-a-printer/).
{% endhint %}

***

### <mark style="color:blue;">Password in Description Field</mark>

<mark style="color:green;">**Finding Passwords in the Description Field using Get-Domain User**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
```
{% endcode %}

***

### <mark style="color:blue;">PASSWD\_NOTREQD Field</mark>

* Dans **Active Directory**, certains comptes de domaine peuvent avoir l’attribut **`passwd_notreqd`** activé dans **`userAccountControl`**.
* Quand ce drapeau est activé, l’utilisateur **n’est pas soumis à la politique de mot de passe** :
  * il peut avoir un mot de passe très court,
  * voire **aucun mot de passe** si le domaine autorise les mots de passe vides.
* Cela peut arriver :
  * intentionnellement (ex. un administrateur met un mot de passe vide pour éviter d’être appelé hors horaires),
  * accidentellement (ex. utilisateur qui appuie sur _Entrée_ au lieu de saisir un mot de passe),
  * ou via un **logiciel tiers** qui configure ce flag lors de son installation et oublie de le désactiver.
* Attention ⚠️ : ce drapeau activé **ne veut pas dire automatiquement** que le compte n’a pas de mot de passe, seulement qu’il n’y est **pas obligé**.
* Lors d’un audit, il est important de :
  * **lister tous les comptes** avec ce drapeau,
  * **tester** s’ils sont accessibles sans mot de passe,
  * **documenter** cette configuration dans le rapport (car elle représente un risque).

<mark style="color:green;">**Checking for PASSWD\_NOTREQD Setting using Get-DomainUser**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```
{% endcode %}

***
