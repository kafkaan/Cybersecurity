---
description: >-
  Le protocole SMB (Server Message Block) est un protocole client-serveur qui
  régule l'accès aux fichiers, aux répertoires entiers sur un reseau.
cover: ../../../.gitbook/assets/int.jpg
coverY: 0
---

# SMB

> Le protocole SMB (Server Message Block) est un <mark style="color:orange;">**protocole client-serveur qui régule l'accès aux fichiers, aux répertoires entiers et à d'autres ressources réseau**</mark> telles que les imprimantes, les routeurs ou les interfaces disponibles sur le réseau.&#x20;
>
> Le protocole SMB permet également &#x64;**'échanger des informations entre différents processus système**. Il a été rendu public avec le système d'exploitation réseau LAN Manager et LAN Server d'OS/2. Depuis, son principal domaine d'application est la série des systèmes d'exploitation Windows, dont les services réseau prennent en charge SMB de manière rétrocompatible. Le projet de logiciel libre Samba permet également d'utiliser SMB sous Linux et Unix, facilitant ainsi la communication multiplateforme via SMB.

## <mark style="color:red;">**Les versions de SMB**</mark>&#x20;

* _**CIFS**_ : Windows NT 4.0
* _**SMB 1.0**_ : Windows 2000
* _**SMB 2.0**_ : Windows Vista, Windows Server 2008
* _**SMB 2.1**_ : Windows 7, Windows Server 2008 R2
* _**SMB 3.0**_ : Windows 8, Windows Server 2012
* _**SMB 3.0.2**_ : Windows 8.1, Windows Server 2012 R2
* _**SMB 3.1.1**_ : Windows 10, Windows Server 2016

***

## <mark style="color:red;">Samba</mark>

{% hint style="warning" %}
<mark style="color:green;">**Samba**</mark>

* **Qu'est-ce que c'est ?** : Samba est un <mark style="color:orange;">**logiciel qui permet aux systèmes Linux et Unix de partager des fichiers et des imprimantes avec des systèmes Windows**</mark>. Il utilise le protocole SMB/CIFS (Server Message Block/Common Internet File System) pour cette communication.
* **Comment ça marche ?** : Quand vous installez Samba sur un système Linux, il permet à ce système d'agir comme un serveur de fichiers pour les clients Windows. Ainsi, un dossier partagé sur un ordinateur Linux peut être accédé depuis un ordinateur Windows, et vice versa.

**NetBIOS&#x20;**<mark style="color:green;">**:**</mark>

* **Qu'est-ce que c'est ?** : NetBIOS (Network Basic Input/Output System) est un protocole ancien qui <mark style="color:orange;">**permet aux ordinateurs sur un réseau local de se découvrir**</mark> et de communiquer en utilisant des noms d'hôtes simples, au lieu des adresses IP.Il utilisait les _**ports TCP/UDP 137, 138 et 139**<mark style="color:orange;">**.**</mark>_
* **Fonctionnement avec Samba** : NetBIOS peut être utilisé par Samba pour la découverte des noms d'hôtes. Cela signifie que, grâce à NetBIOS, les ordinateurs sur le réseau peuvent trouver les autres ordinateurs et leurs ressources partagées par leurs noms simples (par exemple, "MAISON" ou "BUREAU").

<mark style="color:green;">**NBNS et WINS :**</mark>

* **NBNS (NetBIOS Name Service)** : C'est un service qui permet de résoudre les noms NetBIOS en adresses IP. Chaque ordinateur en ligne doit enregistrer son nom NetBIOS pour être découvert par d'autres machines.
* **WINS (Windows Internet Name Service)** : C'est une amélioration du service NBNS. WINS est utilisé principalement dans les réseaux Windows pour résoudre les noms NetBIOS en adresses IP de manière plus efficace.

<mark style="color:green;">**Comment Samba utilise NetBIOS :**</mark>

* Lorsque vous configurez Samba sur un système Linux, il peut utiliser NetBIOS pour permettre aux ordinateurs Windows de découvrir et d'accéder aux ressources partagées par leur nom NetBIOS.
* Par exemple, si vous avez un ordinateur Linux avec Samba installé et un dossier partagé appelé "PHOTOS", les ordinateurs Windows sur le même réseau peuvent voir et accéder à ce dossier en utilisant le nom NetBIOS de l'ordinateur Linux.
{% endhint %}

#### <mark style="color:green;">**Samba 3 - Membre d'un Domaine Active Directory**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

* **Samba 3** a introduit la capacité pour un serveur Samba de devenir un <mark style="color:orange;">**membre à part entière d'un domaine Active Directory**</mark>. Cela permet au serveur Samba de participer à l'infrastructure Active Directory, en utilisant les mêmes services d'authentification et de gestion des utilisateurs que les serveurs Windows.

#### <mark style="color:green;">**Samba 4 - Contrôleur de Domaine Active Directory**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

* **Samba 4** a étendu les fonctionnalités pour permettre à un serveur Samba de fonctionner comme un <mark style="color:orange;">**contrôleur de domaine Active Directory**</mark>. En tant que contrôleur de domaine, Samba 4 peut gérer les utilisateurs, les groupes, les politiques de sécurité, et fournir des services d'authentification à d'autres machines dans le domaine, tout comme le ferait un serveur Windows.

***

## <mark style="color:red;">**Évolution de SMB**</mark> <mark style="color:red;"></mark><mark style="color:red;">:</mark>

* Les premières versions de SMB (jusqu'à SMB1) utilisaient NetBIOS sur les ports 137, 138 et 139 pour fonctionner.
* **SMB1** : Utilise NetBIOS sur les <mark style="color:orange;">**ports TCP/UDP 137, 138, 139.**</mark>
* **SMB2 et SMB3** : Introduits par Microsoft avec Windows Vista et Windows Server 2008 (pour SMB2), puis améliorés dans les versions ultérieures (SMB3). Ces versions plus récentes de SMB n'ont plus besoin de NetBIOS et utilisent directement le port **TCP 445**<mark style="color:orange;">.</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>SMB Version</strong></td><td><strong>Supported</strong></td><td><strong>Features</strong></td></tr><tr><td>CIFS</td><td>Windows NT 4.0</td><td>Communication via NetBIOS interface</td></tr><tr><td>SMB 1.0</td><td>Windows 2000</td><td>Direct connection via TCP</td></tr><tr><td>SMB 2.0</td><td>Windows Vista, Windows Server 2008</td><td>Performance upgrades, improved message signing, caching feature</td></tr><tr><td>SMB 2.1</td><td>Windows 7, Windows Server 2008 R2</td><td>Locking mechanisms</td></tr><tr><td>SMB 3.0</td><td>Windows 8, Windows Server 2012</td><td>Multichannel connections, end-to-end encryption, remote storage access</td></tr><tr><td>SMB 3.0.2</td><td>Windows 8.1, Windows Server 2012 R2</td><td></td></tr><tr><td>SMB 3.1.1</td><td>Windows 10, Windows Server 2016</td><td>Integrity checking, AES-128 encryption</td></tr></tbody></table>

***

## <mark style="color:red;">Configuration SMB</mark>

```bash
cat /etc/samba/smb.conf | grep -v "#\|\;" 
```

1. **Configuration globale :**
   * **`workgroup`** : Le groupe de travail ou domaine auquel le serveur Samba appartient.
   * **`server string`** : Le nom du serveur qui apparaît lorsqu'un client se connecte.
   * **`log file`** : Le fichier de journalisation.
   * **`max log size`** : La taille maximale du fichier journal en kilo-octets.
   * **`server role`** : Le rôle du serveur (par exemple, serveur autonome).
   * **`unix password sync`** : Synchroniser le mot de passe UNIX avec le mot de passe SMB.
   * **`usershare allow guests`** : Autoriser les utilisateurs non authentifiés à accéder aux partages définis.
2. **Configuration des partages :**
   * **`[sharename]`** : Le nom du partage réseau.
   * **`path`** : Le chemin d'accès au répertoire que l'utilisateur peut accéder.
   * **`browseable`** : Déterminer si le partage doit être affiché dans la liste des partages disponibles.
   * **`guest ok`** : Autoriser la connexion au partage sans mot de passe.
   * **`read only`** : Autoriser les utilisateurs à lire les fichiers uniquement.
   * **`create mask`** : Les autorisations à définir pour les nouveaux fichiers créés.

Exemple de configuration de base&#x20;

{% code overflow="wrap" fullWidth="true" %}
```bash
[global]
   workgroup = DEV.INFREIGHT.HTB  # Définit le nom du groupe de travail ou du domaine auquel le serveur Samba appartient.
   server string = DEVSMB  # Spécifie une chaîne de description pour le serveur, affichée lors de la connexion.
   log file = /var/log/samba/log.%m  # Définit le chemin du fichier de journalisation pour Samba, avec %m remplacé par le nom de l'hôte du client.
   max log size = 1000  # Limite la taille maximale du fichier de journal en kilo-octets.
   logging = file  # Indique que les journaux doivent être écrits dans des fichiers.
   panic action = /usr/share/samba/panic-action %d  # Définie l'action à entreprendre si Samba rencontre une erreur critique, %d est remplacé par le numéro de processus.

   server role = standalone server  # Indique que le serveur Samba fonctionne en tant que serveur autonome.
   obey pam restrictions = yes  # Indique que Samba doit respecter les restrictions définies par PAM pour les opérations de gestion des mots de passe.
   unix password sync = yes  # Active la synchronisation des mots de passe UNIX et SMB.
   passwd program = /usr/bin/passwd %u  # Définit la commande utilisée pour changer les mots de passe UNIX, %u est remplacé par le nom d'utilisateur.
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .  # Script de conversation utilisé par Samba pour interagir avec la commande de changement de mot de passe.
   pam password change = yes  # Indique que les changements de mot de passe doivent être gérés par PAM.
   map to guest = bad user  # Spécifie que les tentatives de connexion échouées doivent être mappées à l'utilisateur invité.
   usershare allow guests = yes  # Permet aux utilisateurs non authentifiés d'accéder aux partages définis par les utilisateurs.

[printers]
   comment = All Printers  # Description du partage d'imprimantes.
   browseable = no  # Indique que ce partage ne doit pas apparaître dans la liste des partages disponibles.
   path = /var/spool/samba  # Chemin du répertoire utilisé pour les travaux d'impression.
   printable = yes  # Spécifie que ce partage est destiné à l'impression.
   guest ok = no  # Indique que l'accès invité n'est pas autorisé pour ce partage.
   read only = yes  # Les utilisateurs ne peuvent que lire les fichiers, pas les modifier.
   create mask = 0700  # Définit les permissions des nouveaux fichiers créés (propriétaire a tous les droits, les autres n'ont aucun droit).

[print$]
   comment = Printer Drivers  # Description du partage pour les pilotes d'imprimante.
   path = /var/lib/samba/printers  # Chemin du répertoire contenant les pilotes d'imprimante.
   browseable = yes  # Indique que ce partage doit apparaître dans la liste des partages disponibles.
   read only = yes  # Les utilisateurs peuvent seulement lire les fichiers, pas les modifier.
   guest ok = no  # Indique que l'accès invité n'est pas autorisé pour ce partage.

```
{% endcode %}

{% code fullWidth="true" %}
```bash
[global]
   workgroup = MON_GROUPE
   server string = Mon serveur Samba
   log file = /var/log/samba/log.%m
   max log size = 1000
   server role = standalone server
   unix password sync = yes
   usershare allow guests = yes

[MonPartage]
   path = /chemin/vers/mon/partage
   browseable = yes
   guest ok = no
   read only = no
   create mask = 0755

```
{% endcode %}

***

## <mark style="color:red;">**Smbclient**</mark>&#x20;

*   <mark style="color:orange;">**Lister les partages d'un serveur SMB :**</mark>

    ```
    smbclient -N -L //IP_du_serveur

    ```
*   <mark style="color:orange;">**Se connecter à un partage SMB :**</mark>

    ```
    smbclient //IP_du_serveur/nom_du_partage

    ```
* Quelques commandes utiles dans **`smbclient`** :
  * **`help`** : affiche la liste des commandes disponibles.
  * **`ls`** : liste les fichiers et dossiers du partage.
  * **`get nom_du_fichier`** : télécharge un fichier du partage.
  * **`put nom_du_fichier`** : envoie un fichier sur le partage.
  * **`mkdir nom_du_dossier`** : crée un nouveau dossier dans le partage.
  * **`rmdir nom_du_dossier`** : supprime un dossier du partage.
  * **`rm nom_du_fichier`** : supprime un fichier du partage.
  * **`!commande`** : exécute une commande locale (par exemple, **`!ls`** pour lister les fichiers locaux).
  * **`smbstatus`** : Affiche l'état des connexions SMB et des fichiers verrouillés :

***

## <mark style="color:red;">Footprinting SMB</mark>

### <mark style="color:blue;">Nmap</mark>&#x20;

Mais elle est pas assez efficace

* `sudo nmap 10.129.14.128 -sV -sC -p139,445`

***

### <mark style="color:blue;">Rpcclient</mark>&#x20;

{% hint style="warning" %}
<mark style="color:green;">**Qu'est-ce que le RPC (Remote Procedure Call) ?**</mark>

**Remote Procedure Call (RPC)** est <mark style="color:orange;">**une méthode utilisée pour permettre à un programme sur un ordinateur (le client) d'exécuter du code sur un autre ordinateur (le serveur).**</mark> Cela se fait via un réseau. Voici une comparaison pour mieux comprendre :

Imaginez que vous travaillez dans un bureau et que vous devez demander à un collègue (le serveur) de faire quelque chose pour vous, comme imprimer un document. Vous lui envoyez une demande (l'appel) et il vous renvoie le document imprimé (la réponse).

***

<mark style="color:green;">**Comment fonctionne le RPC ?**</mark>

1. **Le Client envoie une demande (appel) au Serveur** :
   * Le client demande au serveur d'exécuter une fonction spécifique.
   * Cette demande inclut des paramètres (informations nécessaires pour exécuter la fonction).
2. **Le Serveur reçoit la demande et exécute la fonction** :
   * Le serveur traite la demande, exécute la fonction demandée avec les paramètres fournis.
3. **Le Serveur renvoie le résultat au Client** :
   * Après avoir exécuté la fonction, le serveur envoie le résultat de cette fonction au client.

***

<mark style="color:orange;">**Exemple Simple de RPC**</mark>

Supposons que vous avez une fonction sur le serveur qui ajoute deux nombres.

1. **Client** : "S'il te plaît, ajoute 5 et 3."
2. **Serveur** : "OK, je vais ajouter 5 et 3."
3. **Serveur** : "Le résultat est 8."
4. **Client** : "Merci pour le résultat de 8."

***

<mark style="color:green;">**Qu'est-ce que**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`rpcclient`**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**?**</mark>

`rpcclient` est un outil qui permet d'interagir avec des services RPC sur des serveurs Windows. Il fait partie du projet Samba et permet d'envoyer des requêtes spécifiques aux services RPC sur les serveurs Windows.

**Utilisation de `rpcclient` avec des exemples**

Pour utiliser `rpcclient`, vous devez avoir accès à un serveur Windows et des informations d'identification (nom d'utilisateur et mot de passe).

**Exemple 1 : Connexion à un Serveur**

```bash
rpcclient -U "username%password" server_address
```

* **username** : Votre nom d'utilisateur.
* **password** : Votre mot de passe.
* **server\_address** : L'adresse IP ou le nom du serveur.

**Exemple 2 : Lister les Partages SMB**

Une fois connecté, vous pouvez lister les partages SMB disponibles sur le serveur.

```bash
rpcclient $> srvsvc enumshares
```

**Exemple 3 : Lister les Utilisateurs**

Vous pouvez également lister les utilisateurs sur le serveur.

```bash
rpcclient $> enumdomusers
```
{% endhint %}

On va ainsi utiliser **rpcclient** SMB utilise les services MS-RPC pour communiquer avec d'autres ordinateurs sur le réseau. Rpcclient est un outil qui vous permet d'interagir manuellement avec le serveur SMB et d'envoyer des requêtes spécifiques en utilisant le protocole MS-RPC. En d'autres termes, rpcclient vous permet de "parler" directement au serveur SMB en utilisant le langage RPC pour demander des actions et obtenir des réponses.

* `rpcclient -U "" 10.129.14.128`

<mark style="color:orange;">**Exemples de requêtes et leur description**</mark>

* **`srvinfo`**: Informations sur le serveur.
* **`enumdomains`**: Enumère tous les domaines déployés sur le réseau.
* **`querydominfo`**: Fournit des informations sur le domaine, le serveur et les utilisateurs des domaines déployés.
* **`netshareenumall`**: Enumère tous les partages disponibles.
* **`netsharegetinfo`**\<share> : Fournit des informations sur un partage spécifique.
* **`enumdomusers`**: Enumère tous les utilisateurs du domaine.
* **`queryuser`**\<RID> : Fournit des informations sur un utilisateur spécifique.

<mark style="color:orange;">**Risques et précautions**</mark>

* L'accès anonyme aux services peut mettre tout le réseau en danger si trop de permissions ou de visibilité sont accordées.
* Les humains étant plus enclins à l'erreur que les processus informatiques correctement configurés, le manque de sensibilisation à la sécurité et la paresse peuvent souvent conduire à des mots de passe faibles, faciles à craquer.
* Les services réseaux exposés aux utilisateurs anonymes peuvent fuiter des informations sensibles.
* Ces informations peuvent mener à la découverte d'autres utilisateurs et à des attaques par force brute.

***

#### <mark style="color:green;">**Rpcclient - User Enumeration**</mark>

* Permet d'énumérer les utilisateurs sur le réseau.
* Exemple de commande : **`rpcclient $> enumdomusers`**
* Possibilité d'obtenir des informations détaillées sur les utilisateurs avec la commande **`queryuser`**.

#### <mark style="color:green;">**Rpcclient - Group Information**</mark>

* Permet d'obtenir des informations sur les groupes.
* Exemple de commande : **`rpcclient $> querygroup 0x201`**

#### <mark style="color:green;">**Brute Forcing User RIDs**</mark>

* Utilisation d'une boucle for pour brute forcer les RIDs des utilisateurs et obtenir des informations.
* Exemple de commande :&#x20;

{% code title="" overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

```
{% endcode %}

***

### <mark style="color:blue;">**Impacket -**</mark> [<mark style="color:blue;">**Samrdump.py**</mark>](http://samrdump.py)

* Un script Python pour obtenir des informations sur les utilisateurs.
* Exemple de commande : **`samrdump.py 10.129.14.128`**

### <mark style="color:blue;">**SMBMap et CrackMapExec**</mark>

* Outils pour l'énumération des services SMB.
* Exemple de commandes : **`smbmap -H 10.129.14.128`** et **`crackmapexec smb 10.129.14.128 --shares -u '' -p ''`**

### <mark style="color:blue;">**Enum4Linux-ng**</mark>

* Un outil d'énumération basé sur enum4linux.
* Automatise de nombreuses requêtes pour obtenir des informations sur les services réseaux.
* Exemple de commande : **`./enum4linux-ng.py 10.129.14.128 -A`**
