# Élévation de privilèges via DPAPI (Data Protection API)

***

### <mark style="color:blue;">🧠 1. Qu’est-ce que DPAPI ?</mark>

{% hint style="warning" %}
**DPAPI (Data Protection API)** est une fonctionnalité Windows utilisée pour **chiffrer et stocker localement** des données sensibles, comme :

* Mots de passe Wi-Fi
* Credentials réseau
* Secrets du Credential Manager
* Clés privées

Ces données sont **chiffrées avec une Master Key unique**, propre à l'utilisateur, stockée dans le profil local.
{% endhint %}

***

### <mark style="color:blue;">📁 2. Où se trouvent les fichiers utiles ?</mark>

Tous les fichiers liés à DPAPI sont cachés dans le dossier **AppData** de l'utilisateur :

<table data-full-width="true"><thead><tr><th>Type de données</th><th>Chemin</th></tr></thead><tbody><tr><td>🗝️ Master Key</td><td><code>C:\Users\&#x3C;user>\AppData\Roaming\Microsoft\Protect\&#x3C;SID>\</code></td></tr><tr><td>🔑 Credentials chiffrés</td><td><code>C:\Users\&#x3C;user>\AppData\Local\Microsoft\Credentials\</code></td></tr><tr><td>🧳 Vault (gestionnaire de mots de passe)</td><td><code>C:\Users\&#x3C;user>\AppData\Local\Microsoft\Vault\</code></td></tr><tr><td>🌐 Credentials réseau</td><td><code>C:\Users\&#x3C;user>\AppData\Roaming\Microsoft\Credentials\</code></td></tr></tbody></table>

***

### <mark style="color:blue;">🛠️ 3. Étapes d’exploitation (CTF-style)</mark>

**🔍 Étape 1 : Découverte de comptes**

* On identifie un **compte utilisateur standard** (ex : `steph.cooper`)
* Et un **compte \_adm** (ex : `steph.cooper_adm`) qui a des privilèges élevés

**📦 Étape 2 : Trouver un mot de passe (via fichier backup, XML, etc.)**

* Un mot de passe est trouvé pour `steph.cooper`
* On explore ensuite son dossier AppData

**🧪 Étape 3 : Extraction de la master key**

Si accès direct impossible :

{% code fullWidth="true" %}
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\<SID>\<GUID>"))
```
{% endcode %}

Puis on la télécharge via Evil-WinRM, la décode en base64 et on obtient `master.key`

**🔐 Étape 4 : Rechercher les credentials chiffrés**

* Fichiers dans Credentials ou Vault
* On les télécharge pour les déchiffrer avec la master key

***

## <mark style="color:red;">Architecture des Dossiers Windows & DPAPI</mark>

***

### <mark style="color:blue;">🗂️ I. Architecture générale des dossiers utilisateur Windows</mark>

Quand un utilisateur se connecte à une machine Windows, un **profil utilisateur** est créé sous :

```plaintext
C:\Users\<nom_utilisateur>\
```

À l’intérieur de ce dossier, on retrouve une structure bien définie :

```
C:\Users\<username>\
├── 3D Objects
├── AppData
│   ├── Local
│   ├── LocalLow
│   └── Roaming
├── Contacts
├── Desktop
├── Documents
├── Downloads
├── Favorites
├── Links
├── Music
├── Pictures
├── Saved Games
├── Searches
├── Videos
├── ntuser.dat
```

***

### <mark style="color:blue;">📁 II. AppData : le cerveau caché</mark>

#### <mark style="color:green;">Qu'est-ce que</mark> <mark style="color:green;"></mark><mark style="color:green;">`AppData`</mark> <mark style="color:green;"></mark><mark style="color:green;">?</mark>

`AppData` est un **dossier caché** qui contient les **paramètres, cache, mots de passe, et fichiers de session** des applications utilisateur.

> 📌 Emplacement :

```
C:\Users\<username>\AppData\
```

#### Sous-dossiers de AppData

| Dossier    | Rôle                                                                |
| ---------- | ------------------------------------------------------------------- |
| `Local`    | Cache local, spécifique à la machine (n’est pas synchronisé)        |
| `LocalLow` | Même but que Local mais avec restrictions de sécurité (sandbox, IE) |
| `Roaming`  | Données qui suivent l'utilisateur (via AD) dans un domaine          |

***

### <mark style="color:blue;">🔐 III. Focus spécial :</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`AppData\Roaming\Microsoft`</mark>

C’est **ici que le système et les applications stockent des secrets chiffrés**.

#### 🗄️ Dossiers sensibles :

```plaintext
AppData\Roaming\Microsoft\
├── Credentials
├── Protect
├── Windows\Vault\
```

***

### <mark style="color:blue;">🧬 IV. DPAPI : Data Protection API</mark>

#### <mark style="color:green;">🧩 Qu’est-ce que DPAPI ?</mark>

DPAPI est un **framework natif Windows** utilisé pour **chiffrer et stocker des secrets** pour l'utilisateur ou le système.

➡️ Exemples de données protégées :

* Mots de passe Wi-Fi
* Sessions RDP
* Jetons d'auth (Chrome, IE, Edge)
* Mots de passe enregistrés par Windows

> 📌 Les données sont **chiffrées avec une clé dérivée du mot de passe de session** de l'utilisateur.

***

### <mark style="color:blue;">📦 V. Emplacements liés à DPAPI</mark>

#### 📁 `AppData\Roaming\Microsoft\Credentials`

Contient les **credential blobs** :

* Fichiers nommés en **hexadecimal** (ex: `772275FAD58525253490A9B0039791D3`)
* Environ 400–700 bytes
* **Contenu chiffré** via DPAPI

📦 Exemple de contenu :

```plaintext
C:\Users\john\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3
```

***

#### <mark style="color:blue;">📁</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`AppData\Roaming\Microsoft\Protect\<SID>`</mark>

Ce dossier contient :

* 🔑 **Master Keys** : clés utilisées pour déchiffrer les blobs de `Credentials`
* 📌 `Preferred` : fichier qui indique la clé actuellement utilisée
* 🔁 `BK-*` : backup keys

📦 Exemple :

```plaintext
C:\Users\john\AppData\Roaming\Microsoft\Protect\S-1-5-21-XXXX-XXXX-XXXX-XXXX\
├── 08949382-134f-4c63-b93c-ce52efc0aa88 (masterkey)
├── BK-VOLEUR (backup)
├── Preferred
```

***

#### <mark style="color:blue;">📁</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`Windows\Vault`</mark>

Vault est utilisé par Windows pour stocker :

* Jetons WebAuthN
* Sessions de sites web
* Authentifications automatiques

📦 Emplacement :

```plaintext
C:\Users\<username>\AppData\Local\Microsoft\Vault
```

***

### <mark style="color:blue;">🧪 VI. Extraction Post-Exploitation</mark>

#### <mark style="color:green;">1.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Extraire les DPAPI blobs**</mark>

Avec un accès disque :

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Credentials" -Force
```

#### 2. **Récupérer les masterkeys**

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Protect" -Recurse
```

***

### <mark style="color:blue;">🔓 VII. Déchiffrement DPAPI (Post-exploitation)</mark>

Pour déchiffrer :

#### <mark style="color:green;">1. Récupérer le SID :</mark>

```powershell
Get-ADUser john | Select-Object SID
```

#### <mark style="color:green;">2. Utiliser Impacket</mark> <mark style="color:green;"></mark><mark style="color:green;">`dpapi.py`</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

```bash
dpapi.py masterkey -file <masterkey_file> \
  -sid <S-1-5-21-...> \
  -password '<user_password>'
```

<mark style="color:green;">Puis :</mark>

```bash
dpapi.py credential -file <blob_file> -key <decrypted_masterkey>
```

***

### <mark style="color:blue;">💥 VIII. Résumé – Comment tout s’imbrique :</mark>

```
User logs in
   └──→ Windows dérive une clé depuis son password
        └──→ Cette clé est utilisée pour chiffrer une MasterKey
               └──→ Cette MasterKey est utilisée pour chiffrer le blob DPAPI
                        └──→ Le blob est stocké dans AppData\Roaming\Microsoft\Credentials
```

<mark style="color:green;">**📌 Pour exfiltrer des secrets :**</mark>

* Récupère le masterkey
* Cracke ou utilise le mot de passe/sid
* Déchiffre les blobs
* ➡️ Tu obtiens des identifiants plaintext 🎯

***

| Outil                 | Rôle                                      |
| --------------------- | ----------------------------------------- |
| `dpapi.py` (Impacket) | Déchiffrement masterkey & credential blob |
| `mimikatz`            | Extraction des masterkeys depuis LSASS    |
| `vaultcmd`            | Gestion du Windows Vault                  |
| `SharpDPAPI`          | Outil Red Team complet pour DPAPI         |
| `lsadump`             | Extraction LSA secrets                    |
| `secretsdump.py`      | Dump de ntds.dit, SYSTEM, SECURITY        |

***
