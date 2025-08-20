# Kerberoasting - from Linux

### <mark style="color:red;">Kerberoasting Overview</mark>

Le **Kerberoasting** est une technique utilisée pour le **mouvement latéral** et l’**escalade de privilèges** dans les environnements **Active Directory**. L'attaque cible les **comptes Service Principal Name (SPN)**, qui sont des identifiants uniques utilisés par **Kerberos** pour associer une instance de service à un compte de service spécifique.

<mark style="color:green;">**Fonctionnement de l'attaque :**</mark>

1. **Les SPN et les comptes de service** : Ces comptes sont souvent des comptes de **domaine** utilisés pour exécuter des services, afin de surmonter les limitations des comptes intégrés comme **NT AUTHORITY\LOCAL SERVICE**.
2. **Demande de ticket Kerberos** : Tout utilisateur de domaine peut demander un ticket Kerberos pour un compte de service dans le même domaine, et cette procédure peut aussi être effectuée à travers des relations de confiance entre forêts.
3. **Accès requis pour l'attaque** : Pour effectuer une attaque **Kerberoasting**, il suffit d’avoir :
   * Le mot de passe en **texte clair** ou son **hachage NTLM**.
   * Un accès **shell** dans le contexte d’un compte utilisateur de domaine.
   * Un accès **SYSTEM** sur une machine membre du domaine.

<mark style="color:green;">**Risques liés aux comptes de service :**</mark>

* Les comptes de service dans **Active Directory** sont souvent des **administrateurs locaux** ou des comptes avec des privilèges élevés.
* Ces comptes peuvent être **ajoutés à des groupes privilégiés** comme **Domain Admins**.
* Il est courant de trouver des SPN associés à des comptes hautement privilégiés.

<mark style="color:green;">**Processus de l'attaque :**</mark>

1. **Récupération du ticket Kerberos (TGS-REP)** : Bien que l’obtention d’un ticket Kerberos ne permette pas d’exécuter directement des commandes avec ce compte, le ticket est crypté avec le **hachage NTLM** du compte de service.
2. **Attaque par force brute** : En soumettant ce ticket à une attaque par force brute hors ligne, à l’aide d'outils comme **Hashcat**, le mot de passe du service peut être récupéré.
3. **Comptes de service mal configurés** : Les comptes de service ont souvent des mots de passe **faibles** ou **réutilisés**, ce qui facilite le craquage.

<mark style="color:green;">**Exemples d'exploitation :**</mark>

* Si le mot de passe d'un **compte de service SQL Server** est craqué, un attaquant pourrait obtenir des privilèges **d'administrateur local** sur plusieurs serveurs, voire même **Domain Admin**.
* Même si un ticket Kerberos ne permet d’obtenir qu’un compte utilisateur à faible privilège, il peut être utilisé pour créer des **tickets de service** et accéder à des services, comme **MSSQL/SRV01**, en tant que **sysadmin**, permettant l'exécution de code sur le serveur cible.

Cette attaque a été popularisée par la présentation de **Tim Medin** lors de **Derbycon 2014**, où il a exposé le **Kerberoasting** au monde.

***

### <mark style="color:red;">Kerberoasting - Performing the Attack</mark>

L'attaque **Kerberoasting** peut être réalisée de différentes manières selon votre position sur le réseau :

* Depuis un hôte Linux non membre du domaine avec des identifiants de domaine valides.
* Depuis un hôte Linux membre du domaine en tant que root après avoir récupéré le fichier **keytab**.
* Depuis un hôte Windows membre du domaine authentifié en tant qu'utilisateur de domaine.
* Depuis un hôte Windows membre du domaine avec un shell dans le contexte d'un compte de domaine.
* En tant que **SYSTEM** sur un hôte Windows membre du domaine.
* Depuis un hôte Windows non membre du domaine en utilisant **runas /netonly**.

***

### <mark style="color:red;">Efficacy of the Attack</mark>

Le **Kerberoasting** peut être une méthode efficace pour effectuer des mouvements latéraux ou escalader les privilèges dans un domaine, mais la présence de **SPN** (Service Principal Names) ne garantit pas nécessairement un accès. Dans certains cas, après avoir craqué un ticket TGS, on peut obtenir un accès **Domain Admin** directement ou des informations permettant d'aller plus loin dans la compromission du domaine. Dans d'autres situations, bien que plusieurs tickets TGS soient récupérés et certains puissent être craqués, ceux-ci ne sont pas associés à des utilisateurs privilégiés, et l'attaque ne permet pas d'obtenir un accès supplémentaire.

Si l'attaque permet d'obtenir un accès élevé, cela sera marqué comme un **risque élevé** dans le rapport. Par contre, si aucun ticket TGS n'est craqué ou si les mots de passe sont suffisamment forts pour empêcher le craquage (même après plusieurs tentatives avec **Hashcat**), l'attaque serait classée comme un **risque moyen**, en soulignant le danger potentiel des SPN dans le domaine, mais en tenant compte de l'incapacité à prendre le contrôle d'un compte de domaine.

Il est important de faire la distinction entre les différents scénarios dans nos rapports et de savoir ajuster le niveau de risque en fonction des **contrôles de mitigation**, comme l'utilisation de **mots de passe forts**.

***

### <mark style="color:red;">Kerberoasting with GetUserSPNs.py</mark>

Let's start by installing the Impacket toolkit, which we can grab from [Here](https://github.com/SecureAuthCorp/impacket). After cloning the repository, we can cd into the directory and install it as follows:

<mark style="color:orange;">**Installing Impacket using Pip**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo python3 -m pip install .
```
{% endcode %}

<mark style="color:orange;">**Listing GetUserSPNs.py Help Options**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ GetUserSPNs.py -h

```

From the output below, we can see that several accounts are members of the Domain Admins group. If we can retrieve and crack one of these tickets, it could lead to domain compromise. It is always worth investigating the group membership of all accounts because we may find an account with an easy-to-crack ticket that can help us further our goal of moving laterally/vertically in the target domain.

<mark style="color:orange;">**Listing SPN Accounts with GetUserSPNs.py**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```
{% endcode %}

We can now pull all TGS tickets for offline processing using the `-request` flag. The TGS tickets will be output in a format that can be readily provided to Hashcat or John the Ripper for offline password cracking attempts.

<mark style="color:orange;">**Requesting all TGS Tickets**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 
```
{% endcode %}

We can also be more targeted and request just the TGS ticket for a specific account. Let's try requesting one for just the `sqldev` account.

<mark style="color:orange;">**Requesting a Single TGS ticket**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
```
{% endcode %}

With this ticket in hand, we could attempt to crack the user's password offline using Hashcat. If we are successful, we may end up with Domain Admin rights.

To facilitate offline cracking, it is always good to use the `-outputfile` flag to write the TGS tickets to a file that can then be run using Hashcat on our attack system or moved to a GPU cracking rig.

<mark style="color:orange;">**Saving the TGS Ticket to an Output File**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```
{% endcode %}

Here we've written the TGS ticket for the `sqldev` user to a file named `sqldev_tgs`. Now we can attempt to crack the ticket offline using Hashcat hash mode `13100`.

<mark style="color:orange;">**Cracking the Ticket Offline with Hashcat**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
```

We've successfully cracked the user's password as `database!`.&#x20;

<mark style="color:orange;">**Testing Authentication against a Domain Controller**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
```
{% endcode %}

***
