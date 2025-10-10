---
cover: ../../../.gitbook/assets/nfs-in-linux.png
coverY: 0
layout:
  width: default
  cover:
    visible: true
    size: hero
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# NFS

***

## <mark style="color:red;">**Introduction à NFS**</mark>

<mark style="color:orange;">**NFS (Network File System)**</mark> est un <mark style="color:orange;">**protocole de partage de fichiers développé par Sun Microsystems**</mark><mark style="color:orange;">.</mark> Il permet à des systèmes Unix/Linux de partager des répertoires et des fichiers à travers un réseau, les rendant accessibles comme s'ils étaient stockés localement. NFS est principalement utilisé dans des environnements Unix/Linux et est différent de SMB (Server Message Block), qui est utilisé dans les environnements Windows.

**Objectifs principaux :**

* Accéder à des systèmes de fichiers distants comme s'ils étaient locaux.
* Fonctionner entre systèmes Unix/Linux (NFS) et ne pas communiquer directement avec des serveurs SMB.

***

## <mark style="color:red;">**Versions de NFS**</mark>

1. <mark style="color:green;">**NFSv2**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
   * Plus ancien et largement supporté.
   * Fonctionne <mark style="color:orange;">**entièrement sur UDP.**</mark>
   * Moins sécurisé et avec des fonctionnalités limitées.
2. <mark style="color:green;">**NFSv3**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
   * Introduit des améliorations telles que la <mark style="color:orange;">**prise en charge de tailles de fichiers variables**</mark> et un meilleur rapport d'erreurs.
   * Ne pas entièrement compatible avec NFSv2.
   * Utilise <mark style="color:orange;">**UDP et TCP pour la communication.**</mark>
3. <mark style="color:green;">**NFSv4**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
   * Introduit <mark style="color:orange;">**Kerberos pour l'authentification**</mark>, fonctionne **à travers les pare-feu**<mark style="color:orange;">,</mark> ne nécessite plus de portmappers.
   * Supporte les ACLs (Access Control Lists), opérations basées sur l'état, améliore la performance et la sécurité.
   * Premier version à utiliser un protocole stateful (basé sur l'état).
4. <mark style="color:green;">**NFSv4.1 (RFC 8881)**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
   * Supporte les <mark style="color:orange;">**déploiements de serveurs en cluster et l'accès parallèle aux fichiers distribués (pNFS).**</mark>
   * Inclut un mécanisme de troncation de session (NFS multipathing).
   * Utilise un seul port (2049) pour simplifier l'utilisation à travers les pare-feu.

{% hint style="info" %}
<mark style="color:green;">**Qu'est-ce que Kerberos ?**</mark>

Kerberos est un protocole de sécurité qui permet l'authentification sécurisée des utilisateurs et des services dans un réseau. Il est conçu pour permettre à des entités (utilisateurs ou services) de prouver leur identité de manière sécurisée et de s'assurer que les informations échangées sont protégées contre les attaques.

<mark style="color:green;">**Fonctionnement de Kerberos**</mark>

Le fonctionnement de Kerberos repose sur trois composants principaux :

1. **Client** : L'entité qui souhaite accéder à un service (par exemple, un utilisateur qui veut accéder à un fichier sur un serveur).
2. **Serveur d'Authentification (AS)** : Le serveur qui vérifie les identifiants du client et délivre un ticket initial.
3. **Serveur de Tickets de Session (TGS)** : Le serveur qui délivre des tickets de session pour accéder aux services spécifiques après que le client se soit authentifié avec le serveur d'authentification.

**Processus d'Authentification**

1. **Demande d'Authentification** :
   * Le client envoie une demande d'authentification au serveur d'authentification (AS) avec son identifiant.
   * Exemple : Alice veut se connecter à un serveur de fichiers. Elle envoie une demande au serveur d'authentification avec son nom d'utilisateur.
2. **Réponse du Serveur d'Authentification** :
   * L'AS vérifie les informations d'identification (généralement avec un mot de passe ou une clé) et envoie un ticket d'accès au client.
   * Exemple : Alice reçoit un ticket d'accès sécurisé (Ticket-Granting Ticket, TGT) qu'elle peut utiliser pour obtenir un ticket de session pour le serveur de fichiers.
3. **Demande de Ticket de Service** :
   * Le client utilise le TGT pour demander un ticket de session au serveur de tickets de session (TGS) pour le service spécifique (comme un serveur de fichiers).
   * Exemple : Alice utilise son TGT pour demander un ticket de session pour accéder au serveur de fichiers.
4. **Réponse du Serveur de Tickets de Session** :
   * Le TGS vérifie le TGT et, s'il est valide, délivre un ticket de session pour le service demandé.
   * Exemple : Alice reçoit un ticket de session pour le serveur de fichiers, qu'elle utilise pour prouver son identité lorsqu'elle accède au serveur de fichiers.
5. **Accès au Service** :
   * Alice utilise le ticket de session pour accéder au serveur de fichiers. Le serveur de fichiers valide le ticket et accorde l'accès à Alice.
{% endhint %}

***

## <mark style="color:red;">**Protocole RPC et NFS**</mark>

NFS est basé sur le protocole <mark style="color:orange;">**ONC-RPC (Open Network Computing Remote Procedure Call)**</mark><mark style="color:orange;">,</mark> qui utilise les **ports TCP et UDP 111** pour la communication. ONC-RPC permet les appels de procédure à distance entre les clients et les serveurs.

* **XDR (External Data Representation)** est utilisé pour l'échange de données indépendamment du système.
* L'authentification et l'autorisation sont gérées par RPC, pas directement par NFS. NFS utilise les UID/GID UNIX pour la gestion des permissions.

<mark style="color:green;">**Problème de sécurité**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

* Les UID/GID ne doivent pas forcément correspondre entre le client et le serveur, ce qui peut créer des problèmes d'accès non autorisé.

{% hint style="info" %}
<mark style="color:green;">**Fonctionnement de NFS avec RPC**</mark>

Voici une explication détaillée et illustrée du fonctionnement de NFS en utilisant RPC :

1. **Initialisation et Montage** :
   * **Client** : Envoie une requête RPC de type `MOUNT` au serveur NFS pour monter un répertoire partagé.
   * **Serveur** : Répond avec un handle (identifiant unique) pour le répertoire monté.
2. **Recherche de Fichier** :
   * **Client** : Envoie une requête RPC de type `LOOKUP` pour trouver un fichier spécifique dans le répertoire monté.
   * **Serveur** : Répond avec un handle pour le fichier demandé.
3. **Lecture de Fichier** :
   * **Client** : Envoie une requête RPC de type `READ` avec le handle du fichier et la position de lecture.
   * **Serveur** : Répond avec les données du fichier.
4. **Écriture de Fichier** :
   * **Client** : Envoie une requête RPC de type `WRITE` avec le handle du fichier, les données à écrire, et la position d'écriture.
   * **Serveur** : Répond avec le statut de l'opération d'écriture.
5. **Fermeture de Fichier** :
   * **Client** : Envoie une requête RPC de type `CLOSE` pour fermer le fichier après les opérations de lecture/écriture.
   * **Serveur** : Répond avec une confirmation.
6. **Démontage** :
   * **Client** : Envoie une requête RPC de type `UNMOUNT` pour démonter le répertoire.
   * **Serveur** : Répond avec une confirmation.

***

<mark style="color:green;">**Exemple Simplifié**</mark>

```plaintext
  CLIENT                          Serveur NFS
  |                               |
  |--- MOUNT(/export/shared) ---> |  (via RPC)
  |                               |
  | <--- MOUNT_REPLY(handle) ---- |
  |                               |
  |--- LOOKUP(handle, "file") --->|  (via RPC)
  |                               |
  | <--- LOOKUP_REPLY(file_handle)|
  |                               |
  |--- READ(file_handle, offset) ->| (via RPC)
  |                               |
  | <--- READ_REPLY(data) ------- |
  |                               |
  |--- WRITE(file_handle, data) ->| (via RPC)
  |                               |
  | <--- WRITE_REPLY(status) ---- |
  |                               |
  |--- CLOSE(file_handle) ------> | (via RPC)
  |                               |
  | <--- CLOSE_REPLY ------------ |
  |                               |
  |--- UNMOUNT(handle) ---------> | (via RPC)
  |                               |
  | <--- UNMOUNT_REPLY ---------- |
  |                               |
```

***

<mark style="color:green;">**Rôle de RPC dans NFS**</mark>

* **Abstraction** : RPC fournit une abstraction qui permet aux appels de procédures sur le serveur NFS de ressembler à des appels locaux sur le client.
* **Transparence** : Les clients NFS n'ont pas à se soucier des détails de la communication réseau ; ils envoient simplement des requêtes RPC.
* **Simplification** : L'utilisation de RPC simplifie la gestion des opérations distribuées, car toutes les opérations de fichiers sont encapsulées dans des appels RPC.
* **Communication** : RPC est utilisé pour toutes les communications entre le client NFS et le serveur NFS, y compris le montage, la recherche, la lecture, l'écriture et la fermeture de fichiers.
{% endhint %}

***

## <mark style="color:red;">**Configuration par Défaut**</mark>

Le fichier `/etc/exports` contient la configuration des systèmes de fichiers à partager via NFS.

**Exemple de fichier `/etc/exports`** :

{% code overflow="wrap" %}
```bash
# /etc/exports: liste de contrôle d'accès pour les systèmes de fichiers exportés
/srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
/srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
/srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
```
{% endcode %}

**Options de configuration** :

* `rw` : Permissions de lecture et écriture.
* `ro` : Permissions en lecture seule.
* `sync` : Transfert de données synchrone (plus lent).
* `async` : Transfert de données asynchrone (plus rapide).
* `secure` : Utilise des ports inférieurs à 1024.
* `insecure` : Utilise des ports supérieurs à 1024.
* `no_subtree_check` : Désactive la vérification des sous-répertoires.
* `root_squash` : Convertit les permissions root en permissions anonymes pour éviter l'accès root.

**Exemple de commande d'exportation** :

```bash
echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
systemctl restart nfs-kernel-server 
exportfs
```

***

## <mark style="color:red;">**Paramètres Dangereux**</mark>

Certaines options peuvent présenter des risques pour la sécurité :

* **`rw`** : Permissions de lecture et écriture qui peuvent être exploitées.
* **`insecure`** : Utilisation de ports supérieurs à 1024, pouvant être utilisés par des processus non privilégiés.
* **`nohide`** : Exporte un répertoire qui est monté sous un autre répertoire exporté.
* **`no_root_squash`** : Les fichiers créés par root conservent les UID/GID 0, ce qui peut causer des problèmes de sécurité.

**Recommandation** : Tester les configurations dans un environnement sécurisé avant de les déployer en production.

***

## <mark style="color:red;">**Découverte du Service NFS**</mark>

### <mark style="color:blue;">**Ports essentiels**</mark> <mark style="color:blue;"></mark><mark style="color:blue;">:</mark>

* **TCP/UDP 111 (rpcbind)**
* **TCP/UDP 2049 (NFS)**

### <mark style="color:blue;">**Exemple avec Nmap**</mark> <mark style="color:blue;"></mark><mark style="color:blue;">:</mark>

```bash
sudo nmap -p111,2049 -sV -sC 10.129.14.128
```

Affiche les versions et les services en cours d'exécution sur les ports RPC et NFS.

### <mark style="color:blue;">**Utilisation de Nmap NSE Scripts pour NFS**</mark> <mark style="color:blue;"></mark><mark style="color:blue;">:</mark>

```bash
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```

* **`nfs-ls`** : Liste des fichiers sur le volume NFS.
* **`nfs-showmount`** : Affiche les partages NFS disponibles.
* **`nfs-statfs`** : Affiche les statistiques du système de fichiers NFS.

***

## <mark style="color:red;">**Montage et Gestion de NFS**</mark>

#### <mark style="color:green;">**Montage d'un partage NFS**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

```bash
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
```

#### <mark style="color:green;">**Liste des fichiers**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

```bash
ls -l target-NFS
```

#### <mark style="color:green;">**Démonter le partage NFS**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

```bash
sudo umount ./target-NFS
```

**Remarque** : Les options comme `root_squash` peuvent restreindre l'accès même en tant que root.

***
