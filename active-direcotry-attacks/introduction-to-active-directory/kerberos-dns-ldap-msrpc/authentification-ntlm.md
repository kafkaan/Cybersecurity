# Authentification NTLM

### <mark style="color:blue;">Introduction</mark>

En plus de Kerberos et LDAP, Active Directory utilise plusieurs autres méthodes d'authentification qui peuvent être utilisées (et exploitées) par les applications et services dans AD.&#x20;

Celles-ci incluent LM, NTLM, NTLMv1 et NTLMv2. LM et NTLM sont les noms des hachages, tandis que NTLMv1 et NTLMv2 sont des protocoles d'authentification qui utilisent le hachage LM ou NT.

***

### <mark style="color:blue;">Comparaison des Protocoles de Hachage</mark>

<table data-full-width="true"><thead><tr><th>Hash/Protocole</th><th>Technique cryptographique</th><th>Authentification mutuelle</th><th>Type de message</th><th>Tiers de confiance</th></tr></thead><tbody><tr><td>NTLM</td><td>Cryptographie à clé symétrique</td><td>Non</td><td>Nombre aléatoire</td><td>Contrôleur de domaine</td></tr><tr><td>NTLMv1</td><td>Cryptographie à clé symétrique</td><td>Non</td><td>Hachage MD4, nombre aléatoire</td><td>Contrôleur de domaine</td></tr><tr><td>NTLMv2</td><td>Cryptographie à clé symétrique</td><td>Non</td><td>Hachage MD4, nombre aléatoire</td><td>Contrôleur de domaine</td></tr><tr><td>Kerberos</td><td>Cryptographie à clé symétrique et asymétrique</td><td>Oui</td><td>Ticket chiffré utilisant DES, MD5</td><td>Contrôleur de domaine/Centre de distribution de clés (KDC)</td></tr></tbody></table>

***

### <mark style="color:blue;">LM (LAN Manager)</mark>

Les hachages LAN Manager (LM ou LANMAN) sont le plus ancien mécanisme de stockage de mots de passe utilisé par le système d'exploitation Windows. LM a fait ses débuts en 1987 sur le système d'exploitation OS/2. S'ils sont utilisés, ils sont stockés dans la base de données SAM sur un hôte Windows et dans la base de données NTDS.DIT sur un contrôleur de domaine.

#### <mark style="color:green;">Caractéristiques et faiblesses</mark>

* **Désactivé par défaut** depuis Windows Vista/Server 2008 en raison de faiblesses de sécurité significatives
* Encore courant dans les grands environnements avec des systèmes anciens
* **Limite de 14 caractères** pour les mots de passe
* **Non sensible à la casse** - les mots de passe sont convertis en majuscules avant le hachage
* Espace de clés limité à 69 caractères, relativement facile à craquer avec Hashcat

#### <mark style="color:green;">Processus de hachage</mark>

1. Un mot de passe de 14 caractères est divisé en deux morceaux de sept caractères
2. Si le mot de passe fait moins de 14 caractères, il est complété avec des caractères NULL
3. Deux clés DES sont créées à partir de chaque morceau
4. Ces morceaux sont chiffrés en utilisant la chaîne `KGS!@#$%`
5. Deux valeurs de texte chiffré de 8 octets sont créées
6. Ces valeurs sont concaténées pour former le hachage LM

**Faiblesse critique** : Un attaquant n'a besoin de forcer brutalement que sept caractères deux fois au lieu des quatorze caractères complets. Si un mot de passe fait sept caractères ou moins, la seconde moitié du hachage LM sera toujours la même valeur.

**Exemple de hachage LM** : `299bd128c1101fd6`

**Note** : Les systèmes d'exploitation Windows antérieurs à Windows Vista et Windows Server 2008 (Windows NT4, Windows 2000, Windows 2003, Windows XP) stockaient par défaut à la fois le hachage LM et le hachage NTLM du mot de passe d'un utilisateur.

***

### <mark style="color:blue;">NTHash (NTLM)</mark>

Les hachages NT LAN Manager (NTLM) sont utilisés sur les systèmes Windows modernes. C'est un protocole d'authentification par défi-réponse utilisant trois messages :

1. **NEGOTIATE\_MESSAGE** - Le client envoie ce message au serveur
2. **CHALLENGE\_MESSAGE** - Le serveur répond pour vérifier l'identité du client
3. **AUTHENTICATE\_MESSAGE** - Le client répond avec ce message

#### <mark style="color:green;">Stockage et algorithme</mark>

* Stockés localement dans la base de données SAM ou le fichier NTDS.DIT sur un contrôleur de domaine
* Le hachage NT est le **hachage MD4** de la valeur UTF-16 little-endian du mot de passe
* Algorithme : `MD4(UTF-16-LE(password))`

<figure><img src="../../../.gitbook/assets/image (152).png" alt=""><figcaption></figcaption></figure>

#### <mark style="color:green;">Forces et faiblesses</mark>

**Points forts** :

* Considérablement plus forts que les hachages LM
* Support de l'ensemble complet des caractères Unicode (65 536 caractères)

**Faiblesses** :

* Peuvent être forcés brutalement hors ligne avec Hashcat
* L'espace de clés NTLM de 8 caractères peut être forcé en moins de 3 heures avec des attaques GPU
* Les mots de passe plus longs (15+ caractères) peuvent être craqués avec une attaque par dictionnaire hors ligne combinée à des règles
* **Vulnérable à l'attaque pass-the-hash** - un attaquant peut utiliser uniquement le hachage NTLM pour s'authentifier sur les systèmes cibles

#### <mark style="color:green;">Structure d'un hachage NTLM complet</mark>

```
Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::
```

Décomposition :

* **Rachel** = nom d'utilisateur
* **500** = Identifiant Relatif (RID). 500 est le RID connu pour le compte administrateur
* **aad3c435b514a4eeaad3b935b51304fe** = hachage LM (inutilisable si LM est désactivé)
* **e46b9e548fa0d122de7f59fb6d48eaa2** = hachage NT (peut être craqué ou utilisé pour pass-the-hash)

#### <mark style="color:green;">Exemple d'attaque pass-the-hash</mark>

```bash
crackmapexec smb 10.129.41.19 -u rachel -H e46b9e548fa0d122de7f59fb6d48eaa2
```

**Note importante** : Ni LANMAN ni NTLM n'utilisent de sel.

***

### <mark style="color:blue;">NTLMv1 (Net-NTLMv1)</mark>

Le protocole NTLM effectue un défi/réponse entre un serveur et un client en utilisant le hachage NT. NTLMv1 utilise à la fois les hachages NT et LM.

#### Caractéristiques

* Utilisé pour l'authentification réseau
* Le hachage Net-NTLMv1 est créé à partir d'un algorithme de défi/réponse
* Le serveur envoie un nombre aléatoire de 8 octets (défi) au client
* Le client retourne une réponse de 24 octets
* **Ces hachages NE PEUVENT PAS être utilisés pour des attaques pass-the-hash**

#### Algorithme de défi et réponse V1

```
C = défi du serveur de 8 octets, aléatoire
K1 | K2 | K3 = hachage LM/NT | 5-octets-0
réponse = DES(K1,C) | DES(K2,C) | DES(K3,C)
```

#### Exemple de hachage NTLMv1

```
u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
```

***

### <mark style="color:blue;">NTLMv2 (Net-NTLMv2)</mark>

Le protocole NTLMv2 a été introduit pour la première fois dans Windows NT 4.0 SP4 comme alternative plus forte à NTLMv1. C'est le protocole par défaut dans Windows depuis Server 2000.

#### Améliorations

* Renforcé contre certaines attaques d'usurpation auxquelles NTLMv1 est susceptible
* Envoie deux réponses au défi de 8 octets reçu du serveur
* Contient un hachage HMAC-MD5 de 16 octets du défi
* Utilise un défi généré aléatoirement par le client
* Inclut un hachage HMAC-MD5 des informations d'identification de l'utilisateur

#### <mark style="color:green;">Algorithme de défi et réponse V2</mark>

```
SC = défi du serveur de 8 octets, aléatoire
CC = défi du client de 8 octets, aléatoire
CC* = (X, temps, CC2, nom de domaine)
v2-Hash = HMAC-MD5(NT-Hash, nom d'utilisateur, nom de domaine)
LMv2 = HMAC-MD5(v2-Hash, SC, CC)
NTv2 = HMAC-MD5(v2-Hash, SC, CC*)
réponse = LMv2 | CC | NTv2 | CC*
```

#### <mark style="color:green;">Exemple de hachage NTLMv2</mark>

```
admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
```

NTLMv2 est nettement plus difficile à craquer grâce à son algorithme robuste composé de plusieurs étapes.

***

### <mark style="color:blue;">Domain Cached Credentials (MSCache2)</mark>

Dans un environnement AD, les méthodes d'authentification mentionnées nécessitent que l'hôte communique avec le contrôleur de domaine. Microsoft a développé l'algorithme MS Cache v1 et v2 (également connu sous le nom de Domain Cached Credentials - DCC) pour résoudre le problème potentiel d'un hôte joint au domaine incapable de communiquer avec un contrôleur de domaine.

#### Fonctionnement

* Les hôtes sauvegardent les **dix derniers hachages** pour tout utilisateur de domaine qui se connecte avec succès à la machine
* Stockés dans la clé de registre `HKEY_LOCAL_MACHINE\SECURITY\Cache`
* **Ne peuvent PAS être utilisés dans des attaques pass-the-hash**
* **Très lents à craquer** même avec un équipement GPU extrêmement puissant
* Les tentatives de craquage doivent être extrêmement ciblées ou reposer sur un mot de passe très faible

#### Format

```
$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f
```



***
