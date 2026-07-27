# Credential Storage

### <mark style="color:blue;">Linux</mark>

* Linux-based systems handle everything in the **form of a file**.&#x20;
* Accordingly, passwords are also stored encrypted in a file.&#x20;
* This file is called the <mark style="color:orange;">**`shadow`**</mark> file and is located in `/etc/shadow` and is part of the Linux user management system.&#x20;
* These passwords are commonly stored in the form of `hashes`.&#x20;

<mark style="color:orange;">**Shadow File**</mark>

```shell-session
root@htb:~# cat /etc/shadow

...SNIP...
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```

The `/etc/shadow` file has a unique format in which the entries are entered and saved when new users are created.

<table data-full-width="true"><thead><tr><th width="157">-----</th><th width="142">------</th><th>------</th><th>-------</th><th>--------</th><th width="115">--------</th><th width="107">-------</th><th width="121">--------</th><th>-------</th></tr></thead><tbody><tr><td>htb-student:</td><td>$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:</td><td>18955:</td><td>0:</td><td>99999:</td><td>7:</td><td>:</td><td>:</td><td>:</td></tr><tr><td>username</td><td>encrypted password</td><td>day of last change</td><td>min age</td><td>max age</td><td>warning period</td><td>inactivity period</td><td>expiration date</td><td>reserved field</td></tr></tbody></table>

The encryption of the password in this file is formatted as follows:

<table data-full-width="true"><thead><tr><th>FIRST</th><th>SECOND</th><th>THIRD</th></tr></thead><tbody><tr><td><code>$ &#x3C;id></code></td><td><code>$ &#x3C;salt></code></td><td><code>$ &#x3C;hashed></code></td></tr><tr><td><code>$ y</code></td><td><code>$ j9T</code></td><td><code>$ 3QSBB6CbHEu...SNIP...f8Ms</code></td></tr></tbody></table>

The type (`id`) is the cryptographic hash method used to encrypt the password.&#x20;

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>ID</strong></td><td><strong>Cryptographic Hash Algorithm</strong></td></tr><tr><td><code>$1$</code></td><td><a href="https://en.wikipedia.org/wiki/MD5">MD5</a></td></tr><tr><td><code>$2a$</code></td><td><a href="https://en.wikipedia.org/wiki/Blowfish_(cipher)">Blowfish</a></td></tr><tr><td><code>$5$</code></td><td><a href="https://en.wikipedia.org/wiki/SHA-2">SHA-256</a></td></tr><tr><td><code>$6$</code></td><td><a href="https://en.wikipedia.org/wiki/SHA-2">SHA-512</a></td></tr><tr><td><code>$sha1$</code></td><td><a href="https://en.wikipedia.org/wiki/SHA-1">SHA1crypt</a></td></tr><tr><td><code>$y$</code></td><td><a href="https://github.com/openwall/yescrypt">Yescrypt</a></td></tr><tr><td><code>$gy$</code></td><td><a href="https://www.openwall.com/lists/yescrypt/2019/06/30/1">Gost-yescrypt</a></td></tr><tr><td><code>$7$</code></td><td><a href="https://en.wikipedia.org/wiki/Scrypt">Scrypt</a></td></tr></tbody></table>

**The other two files are `/etc/passwd` and `/etc/group`.**

&#x20;In the past, the encrypted password was stored together with the username in the `/etc/passwd` file, but this was increasingly recognized as a security problem because the file can be viewed by all users on the system and must be readable. The `/etc/shadow` file can only be read by the user `root`.

<mark style="color:orange;">**Passwd File**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ cat /etc/passwd

...SNIP...
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

<table data-full-width="true"><thead><tr><th></th><th width="147"></th><th width="119"></th><th width="104"></th><th width="137"></th><th></th><th></th></tr></thead><tbody><tr><td><code>htb-student:</code></td><td><code>x:</code></td><td><code>1000:</code></td><td><code>1000:</code></td><td><code>,,,:</code></td><td><code>/home/htb-student:</code></td><td><code>/bin/bash</code></td></tr><tr><td>username</td><td>password</td><td>uid</td><td>gid</td><td>comment</td><td>home directory</td><td>cmd executed after logging in</td></tr></tbody></table>

The `x` in the password field indicates that the encrypted password is in the `/etc/shadow` file. However, the redirection to the `/etc/shadow` file does not make the users on the system invulnerable because if the rights of this file are set incorrectly, the file can be manipulated so that the user `root` does not need to type a password to log in. Therefore, an empty field means that we can log in with the username without entering a password.

* [Linux User Auth](https://tldp.org/HOWTO/pdf/User-Authentication-HOWTO.pdf)

***

### <mark style="color:blue;">Windows Authentication Process</mark>

#### <mark style="color:green;">Qu'est-ce que le LSA ?</mark>

Le LSA est un **sous-système protégé de Windows** dont le rôle principal est de gérer la sécurité locale d'un ordinateur. On peut le voir comme le "gardien" central de la sécurité sur une machine Windows.

#### <mark style="color:green;">Ses rôles principaux</mark>

**1. Authentification des utilisateurs**\
Le LSA est responsable de l'authentification : c'est lui qui vérifie l'identité des utilisateurs et gère leur connexion (logon) à l'ordinateur local.

**2. Gestion des informations de sécurité**\
Il conserve et gère toutes les informations liées à la sécurité locale de la machine (politiques de sécurité, comptes, etc.).

**3. Traduction Noms ↔ SIDs**\
Le LSA fournit des services permettant de faire la correspondance entre :

* les **noms d'utilisateurs/groupes** (ex: "Jean.Dupont")
* et leurs **SID** (Security Identifier), l'identifiant unique de sécurité utilisé en interne par Windows

**4. Gestion des politiques et comptes**\
Il garde une trace de toutes les politiques de sécurité et des comptes présents sur le système.

**5. Cas particulier : Contrôleur de domaine (DC)**\
Si la machine est un **Contrôleur de Domaine**, alors le LSA ne gère plus seulement les politiques locales, mais celles de **tout le domaine**. Ces informations (comptes, politiques) sont alors stockées dans l'**Active Directory** plutôt que localement.

**6. Contrôle d'accès et audit**\
Enfin, le LSA fournit des services pour :

* **Vérifier les droits d'accès** aux objets (fichiers, dossiers, ressources...)
* **Vérifier les permissions** des utilisateurs
* **Générer des messages de surveillance/audit** (logs de sécurité)

{% hint style="info" %}
<mark style="color:orange;">**Le LSA (Local Security Authority) est une composante de sécurité dans Windows qui :**</mark>

1. **Vérifie les droits d'accès aux objets :**
   * Quand un utilisateur ou un processus demande l'accès à un objet, LSA vérifie si les permissions associées à cet objet permettent cette action.
2. **Contrôle les permissions utilisateur :**
   * Il vérifie si l'utilisateur ou le processus possède les **autorisations nécessaires** (par exemple : appartenir au bon groupe, avoir un droit d'accès explicite, etc.).
3. **Génère des messages de surveillance (auditing) :**
   * Si l'accès est refusé ou accordé, cela peut être consigné dans les journaux de sécurité, selon la politique d’audit configurée.
{% endhint %}

#### <mark style="color:green;">**Windows Authentication Process Diagram**</mark>

{% hint style="info" %}
#### <mark style="color:orange;">Explication du schéma : Processus d'authentification Windows</mark>

Ce diagramme illustre les étapes internes qui se déroulent lorsqu'un utilisateur se connecte (logon) à une machine Windows. Il se lit en suivant les **3 grandes étapes numérotées**.

**🔹 Étape 1 — Capture des identifiants (côté interface)**

* **WinLogon.exe** est le processus responsable de la gestion de la session de connexion (il gère les combinaisons Ctrl+Alt+Suppr, le verrouillage d'écran, etc.)
* Il fait appel à **LogonUI** (l'interface graphique de connexion)
* Qui utilise elle-même un **Credential Provider** (le composant qui fournit le formulaire de saisie : mot de passe, PIN, biométrie, carte à puce...)
* **Secur32.dll** est la bibliothèque qui expose les fonctions SSPI (Security Support Provider Interface) utilisées par WinLogon

➡️ Résultat : les identifiants de l'utilisateur sont récupérés.

**🔹 Étape 2 — Vérification des identifiants (cœur de l'authentification)**

* WinLogon transmet les identifiants à **lsass.exe** (le processus du LSA que nous avons vu précédemment), via la bibliothèque **Lsasrv.dll**
* Lsass consulte les **Authentication Packages** (packages d'authentification) pour savoir comment valider ces identifiants. Deux cas de figure :

**📍 Cas "Local / Non-Domain joined" (poste isolé, hors domaine)**

* Utilise le protocole **NTLM**
* NTLM interroge le **SAM** (Security Account Manager, base de comptes locaux)
* Le SAM s'appuie sur **Samsrv.dll**, lui-même stocké dans le **Registre** Windows
* **Msv1\_0.dll** est le fournisseur d'authentification NTLM

**📍 Cas "Remote / Domain joined" (poste dans un domaine Active Directory)**

Deux protocoles possibles :

* **NTLM** (via **Netlogon**) → interroge **AD Directory Services** (**Ntdsa.dll**)
* **Kerberos** (protocole moderne et préféré en environnement AD) → passe aussi par **Netlogon.dll**

➡️ Résultat : les identifiants sont validés ou rejetés.

**🔹 Étape 3 — Ouverture de la session utilisateur**

Une fois l'authentification réussie, on revient vers WinLogon qui déclenche :

* **CreateDesktop()** : création du bureau (desktop) de session
  * **Load Profile** → **Load Registry** (chargement du profil utilisateur et de sa ruche registre `HKCU`)
  * **userinit.exe** → lance **explorer.exe** (l'interface bureau que l'utilisateur voit)
{% endhint %}

![](https://academy.hackthebox.com/storage/modules/147/Auth_process1.png)

La connexion interactive locale est réalisée grâce à l'interaction entre le processus de connexion (<mark style="color:orange;">**WinLogon**</mark>), le processus de l'interface utilisateur de connexion (<mark style="color:orange;">**LogonUI**</mark>), les fournisseurs d'informations d'identification, LSASS, un ou plusieurs modules d'authentification et SAM ou Active Directory.&#x20;

Les modules d'authentification, dans ce contexte, sont des bibliothèques de liens dynamiques (DLL) qui effectuent les vérifications d'authentification. Par exemple, pour les connexions interactives sur des machines non jointes à un domaine, le module d'authentification utilisé est <mark style="color:orange;">**Msv1\_0.dll**</mark>.

{% hint style="warning" %}
Explication du processus d'authentification sous Windows :

1. **WinLogon.exe** :
   * C'est un processus clé qui gère l'écran de connexion et la première étape de l'authentification. Il charge l'interface **LogonUI** qui permet à l'utilisateur de saisir ses informations d'identification.
2. **LogonUI et Credential Provider** :
   * **LogonUI** est l'interface utilisateur qui permet à l'utilisateur de s'identifier.
   * **Credential Provider** est un composant qui interagit avec le processus **WinLogon** pour recueillir les informations d'identification de l'utilisateur, comme un nom d'utilisateur et un mot de passe.
3. **Interaction avec les systèmes d'authentification (NTLM, Kerberos)** :
   * Si le système est **local** ou **non rejoint à un domaine**, l'authentification se fait via **NTLM** (le protocole d'authentification de Microsoft).
   * Si le système est **joint à un domaine**, l'authentification peut utiliser **Kerberos** ou **NTLM**, selon les paramètres de sécurité.
4. **lsass.exe** :
   * **LSASS** (Local Security Authority Subsystem Service) est un service Windows qui gère les politiques de sécurité locales et l'authentification. Il valide les informations d'identification de l'utilisateur via des <mark style="color:orange;">**packages d'authentification**</mark> comme **NTLM** et **Kerberos**.
5. **Système de gestion des comptes (SAM, Registry)** :
   * Une fois l'utilisateur authentifié, **SAM** (Security Account Manager) et le **registre** sont utilisés pour vérifier les mots de passe et gérer les profils utilisateur sur la machine.
   * **Samsrv.dll** est un fichier système qui aide dans la gestion des comptes et de leurs mots de passe dans **SAM**.
6. **Netlogon et services Active Directory (AD)** :
   * Si l'utilisateur fait partie d'un domaine, **Netlogon** et **AD (Active Directory)** sont utilisés pour authentifier l'utilisateur via des services comme **Netlogon.dll** et **NtDs.dll**.
   * Ces services permettent la validation via **Kerberos** et permettent à l'utilisateur d'accéder à des ressources sur le réseau ou dans le domaine.

***

**Résumé général :**

* **WinLogon.exe** initie l'authentification et passe les informations à **lsass.exe**, qui vérifie les informations d'identification en utilisant soit **NTLM** (pour un système local), soit **Kerberos** (pour un domaine). Après la validation, le profil de l'utilisateur est chargé, et l'accès est accordé aux services en fonction des droits d'accès (via **SAM**, **Netlogon**, **AD**, etc.).
{% endhint %}

#### <mark style="color:green;">**Winlogon**</mark>

:door: Winlogon est un processus de confiance chargé de gérer les interactions liées à la sécurité de l'utilisateur. Ses principales responsabilités incluent :

* Le lancement de LogonUI pour permettre la saisie des mots de passe à la connexion ;
* Le changement des mots de passe ;
* Le verrouillage et le déverrouillage de la station de travail.

Il s'appuie sur les fournisseurs d'informations d'identification installés sur le système pour obtenir le nom de compte ou le mot de passe de l'utilisateur. Ces fournisseurs sont des objets COM situés dans des fichiers DLL.

Winlogon est le seul processus qui intercepte les requêtes de connexion au clavier envoyées via un message RPC de **Win32k.sys**. Lors de la connexion, Winlogon lance immédiatement l'application LogonUI pour afficher l'interface utilisateur de connexion. Une fois qu'il obtient un nom d'utilisateur et un mot de passe des fournisseurs d'informations d'identification, il appelle LSASS pour authentifier l'utilisateur.

{% hint style="info" %}
<mark style="color:green;">🔹</mark> <mark style="color:green;"></mark><mark style="color:green;">**Qu'est-ce que Winlogon ?**</mark>

**Winlogon.exe** est un **processus système essentiel** qui gère tout ce qui concerne la connexion d’un utilisateur à Windows.

> **En gros :**\
> Winlogon est le **gardien de la porte**. Il s'assure que seules les personnes ayant les bons identifiants (nom d'utilisateur/mot de passe) peuvent accéder au système.

***

<mark style="color:orange;">🔹</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**À quoi sert Winlogon ?**</mark>

1. **Affichage de l'écran de connexion** (LogonUI) :
   * Lorsque tu démarres ton PC ou que tu le verrouilles, Winlogon affiche l’écran où tu entres ton mot de passe.
   * Cet écran est généré par **LogonUI.exe**, mais c’est Winlogon qui le lance.
2. **Changement de mot de passe** :
   * Si tu veux changer ton mot de passe Windows, c’est Winlogon qui gère cette action.
3. **Verrouillage/déverrouillage du PC** :
   * Quand tu fais **CTRL + ALT + SUPPR** pour verrouiller ou déverrouiller ton ordinateur, c’est Winlogon qui répond.

***

<mark style="color:orange;">🔹</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**Comment ça marche (étape par étape) ?**</mark>

1. **Démarrage du PC** ➝ Windows charge **Winlogon.exe**.
2. **Affichage de l'écran de connexion** ➝ Winlogon lance **LogonUI.exe**.
3. **Tu entres ton mot de passe** ➝ LogonUI récupère ces informations et les donne à Winlogon.
4. **Winlogon appelle LSASS (Local Security Authority Subsystem Service)** ➝ LSASS vérifie si le mot de passe est correct.
5. **Si c'est correct** ➝ Winlogon démarre ta session (bureau Windows).
6. **Si c'est incorrect** ➝ L'écran affiche "Mot de passe incorrect".

***

<mark style="color:orange;">🔹</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**Winlogon et les fournisseurs d'informations d'identification (Credential Providers)**</mark>

* **Winlogon** ne vérifie pas lui-même les mots de passe.
* Il utilise des **"fournisseurs d'informations d'identification"** (Credential Providers).
* Ces fournisseurs sont des **fichiers DLL** (ex : Msv1\_0.dll) qui contiennent les règles pour vérifier les mots de passe.

👉 **Exemple :**

* Si tu utilises un **mot de passe classique**, c’est la DLL **Msv1\_0.dll** qui s’occupe de la vérification.
* Si tu utilises une **empreinte digitale** ou une **carte à puce**, une autre DLL spécialisée s’en occupe.

***

<mark style="color:orange;">🔹</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**Pourquoi Winlogon est important ?**</mark>

* **Sécurité** : Il empêche l'accès non autorisé.
* **Protection des sessions** : Il gère les verrouillages pour éviter que quelqu’un n’accède à ta session sans autorisation.
* **Stabilité** : Si Winlogon est arrêté, Windows redémarre automatiquement (il est essentiel au système).

***

<mark style="color:orange;">🔹</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**Résumé simplifié :**</mark>

* **Winlogon** ➝ Gère les connexions utilisateur (gardien).
* **LogonUI** ➝ Affiche l’écran de connexion (interface).
* **LSASS** ➝ Vérifie le mot de passe (policier).
* **Credential Providers (DLL)** ➝ Fournit les outils pour vérifier différents types de connexion (clefs).
{% endhint %}

***

#### <mark style="color:green;">**LSASS**</mark>

Le **Local Security Authority Subsystem Service (LSASS)** est une collection de nombreux modules et a accès à tous les processus d'authentification présents dans le fichier&#x20;

`%SystemRoot\System32\Lsass.exe`. Ce service est responsable de :

* La politique de sécurité locale du système ;
* L'authentification des utilisateurs ;
* L'envoi des journaux d'audit de sécurité vers le journal des événements.

En d'autres termes, LSASS constitue un **coffre-fort** pour les systèmes d'exploitation Windows.&#x20;

<table data-header-hidden data-full-width="true"><thead><tr><th>Authentication Packages</th><th></th></tr></thead><tbody><tr><td><code>Lsasrv.dll</code></td><td>The LSA Server service both enforces security policies and acts as the security package manager for the LSA. The LSA contains the Negotiate function, which selects either the NTLM or Kerberos protocol after determining which protocol is to be successful.</td></tr><tr><td><code>Msv1_0.dll</code></td><td>Authentication package for local machine logons that don't require custom authentication.</td></tr><tr><td><code>Samsrv.dll</code></td><td>The Security Accounts Manager (SAM) stores local security accounts, enforces locally stored policies, and supports APIs.</td></tr><tr><td><code>Kerberos.dll</code></td><td>Security package loaded by the LSA for Kerberos-based authentication on a machine.</td></tr><tr><td><code>Netlogon.dll</code></td><td>Network-based logon service.</td></tr><tr><td><code>Ntdsa.dll</code></td><td>This library is used to create new records and folders in the Windows registry.</td></tr></tbody></table>

***

#### <mark style="color:green;">**Session de connexion interactive**</mark>

Chaque session de connexion interactive crée une instance distincte du service Winlogon. L'architecture Graphical Identification and Authentication (GINA) est chargée dans l'espace de processus utilisé par Winlogon, reçoit et traite les informations d'identification, puis invoque les interfaces d'authentification via la fonction **LSALogonUser**.

***

#### <mark style="color:green;">**Base de données SAM**</mark>

:closed\_lock\_with\_key: Le <mark style="color:orange;">**Security Account Manager (SAM)**</mark> est un fichier de base de données dans les systèmes d'exploitation Windows qui stocke les mots de passe des utilisateurs. Il peut être utilisé pour authentifier les utilisateurs locaux et distants.&#x20;

SAM utilise des mesures cryptographiques pour empêcher les utilisateurs non authentifiés d'accéder au système.&#x20;

{% hint style="warning" %}
Les mots de passe des utilisateurs sont stockés sous forme de **hash** dans une structure de registre, soit en tant que hash LM, soit en tant que hash NTLM. Ce fichier est situé dans `%SystemRoot%/system32/config/SAM` et est monté sur **HKLM/SAM**. Des permissions de niveau SYSTEM sont nécessaires pour le consulter.
{% endhint %}

Les systèmes Windows peuvent être affectés à un **groupe de travail** ou à un **domaine** lors de la configuration :

* Si le système appartient à un groupe de travail, il gère la base de données SAM localement et stocke tous les utilisateurs existants dans cette base de données.
* Si le système est joint à un domaine, le **contrôleur de domaine (DC)** doit valider les informations d'identification à partir de la base de données Active Directory (ntds.dit), située dans `%SystemRoot%\ntds.dit`.

***

#### <mark style="color:green;">**Sécurisation du SAM**</mark>

:microscope: Microsoft a introduit une fonctionnalité de sécurité dans **Windows NT 4.0** pour améliorer la protection de la base de données SAM contre les attaques hors ligne. Cette fonctionnalité, appelée **SYSKEY (syskey.exe)**, permet, lorsqu'elle est activée, de chiffrer partiellement la copie sur disque dur du fichier SAM afin que les valeurs de hash des mots de passe de tous les comptes locaux soient chiffrées avec une clé.

<mark style="color:green;">**Credential Manager**</mark>

![](https://academy.hackthebox.com/storage/modules/147/authn_credman_credprov.png)

***

Le **Gestionnaire d'identifiants** (_Credential Manager_) est une fonctionnalité intégrée à tous les systèmes d'exploitation Windows qui permet aux utilisateurs **d'enregistrer les identifiants** qu'ils utilisent pour accéder à divers **ressources réseau** et **sites web**.

{% hint style="info" %}
Les identifiants enregistrés sont **stockés selon le profil utilisateur**, dans un **coffre sécurisé appelé Credential Locker** (_casier à identifiants_).
{% endhint %}

Les identifiants sont **chiffrés** et stockés à l'emplacement suivant :

```powershell-session
PS C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\
```

***

<mark style="color:green;">**NTDS**</mark>

Il est très courant de rencontrer des environnements réseau où les systèmes Windows sont intégrés à un domaine Windows. Cela est fréquent car cela facilite la gestion centralisée de tous les systèmes appartenant à leurs organisations respectives (gestion centralisée). Dans ces cas, les systèmes Windows enverront toutes les demandes de connexion aux contrôleurs de domaine qui font partie du même domaine Active Directory. Chaque contrôleur de domaine héberge un fichier appelé **NTDS.dit**, qui est maintenu synchronisé sur tous les contrôleurs de domaine, à l'exception des contrôleurs de domaine en lecture seule (Read-Only Domain Controllers). **NTDS.dit** est un fichier de base de données qui stocke les données dans Active Directory, y compris, mais sans s'y limiter :

* Comptes utilisateurs (nom d'utilisateur et hachage du mot de passe)
* Comptes de groupes
* Comptes d'ordinateurs
* Objets de stratégie de groupe (Group Policy Objects, GPOs)
