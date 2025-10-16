# ADCS (Certificats)

***

### <mark style="color:red;">Contexte général</mark>

Dans une entreprise, il est courant de mettre en place une **PKI (Public Key Infrastructure)**, c’est-à-dire une **infrastructure à clés publiques** permettant de sécuriser :

* les connexions (ex : HTTPS, VPN),
* l’authentification des utilisateurs,
* la signature de documents,
* le chiffrement des données.

Pour cela, on installe une **Autorité de Certification (CA)** dans le système d'information.

***

### <mark style="color:red;">Qu’est-ce qu’une CA ?</mark>

Une **CA (Certificate Authority)** est un **serveur qui délivre des certificats numériques**.

<mark style="color:green;">**Exemple concret :**</mark>

* L’utilisateur Alice veut prouver son identité pour accéder à un intranet sécurisé.
* Le serveur web exige un **certificat client**.
* Alice a un certificat émis par la **CA de l’entreprise** : donc, elle est reconnue automatiquement.

***

### <mark style="color:red;">Structure d’un certificat</mark>

Un **certificat numérique** contient :

* Le nom du propriétaire (ex : [alice@entreprise.local](mailto:alice@entreprise.local))
* Sa clé publique
* La date de validité
* Le nom de la CA qui l’a émis
* Une **signature numérique** de la CA

> ✅ Un certificat n’est valable **que si la signature est vérifiée par une autorité de confiance**.

***

### <mark style="color:red;">La chaîne de confiance</mark>

Une CA peut être **racine** ou **intermédiaire**.

* La **CA racine** est au sommet.
* Elle peut signer des certificats directement, ou signer une **CA intermédiaire**.
* Les certificats des utilisateurs sont signés par cette chaîne.

#### Exemple :

```
CA Racine
   ↓ signe
CA Intermédiaire
   ↓ signe
Certificat d’Alice
```

Le client fait confiance au certificat d’Alice **parce qu’il a confiance en la CA racine**.

***

### &#x20;<mark style="color:red;">Inscription d’une CA dans l’Active Directory</mark>

Quand une **CA d’entreprise est installée dans un domaine Active Directory**, elle est **automatiquement inscrite dans l’annuaire** :

#### Ce que ça implique :

1. **Le serveur de la CA** est ajouté au groupe **Cert Publishers**.
2. Il devient visible dans la console **adsiedit.msc** :
   * `Configuration > Services > Public Key Services > Certification Authorities`
3. Tous les clients du domaine peuvent **la découvrir automatiquement** via l’AD.

> 🎯 But : éviter de devoir configurer manuellement chaque poste pour reconnaître la CA.

***

### <mark style="color:red;">Déploiement automatique du certificat racine</mark>

Une fois la CA installée :

* Son **certificat racine** est **automatiquement déployé** sur tous les ordinateurs du domaine.

#### Où le trouver ?

* Ouvre `certmgr.msc` (ou `mmc` > Ajouter composant logiciel enfichable > Certificats)
* Regarde dans le magasin :\
  &#xNAN;**« Autorités de certification racines de confiance »**

#### Pas visible ?

* Lancer `gpupdate /force` pour forcer la mise à jour des stratégies de groupe.

***

### &#x20;<mark style="color:red;">À quoi sert le certificat racine ?</mark>

Le **certificat racine** permet de :

1. **Vérifier tous les certificats émis par la CA**
   * Grâce à sa clé publique.
   * Il est **auto-signé**.
2. **Établir une relation de confiance**
   * Si tu fais confiance à la racine, tu fais confiance à tous les certificats qu’elle émet.
3. **Éviter les erreurs de sécurité**
   *   Sans certificat racine, les connexions HTTPS ou l’authentification échouent avec des erreurs du type :

       > “Le certificat n’est pas émis par une autorité de confiance.”

***

### <mark style="color:red;">Exemple d’erreur sans certificat racine</mark>

Un utilisateur tente d’accéder à `https://intranet.entreprise.local`.

* Le site a un certificat SSL, émis par la CA interne.
*   Si le **certificat racine n’est pas installé** sur le poste :

    > ❌ Le navigateur affiche : “Connexion non sécurisée”

En revanche :

*   Si le certificat racine est déployé par Active Directory :

    > ✅ Le navigateur établit une connexion sécurisée sans avertissement.

***

### <mark style="color:red;">Commandes utiles</mark>

| Commande          | Utilité                                         |
| ----------------- | ----------------------------------------------- |
| `certmgr.msc`     | Ouvre le gestionnaire de certificats            |
| `mmc`             | Console pour gérer les certificats manuellement |
| `gpupdate /force` | Forcer l’application des stratégies de groupe   |
| `adsiedit.msc`    | Voir la CA dans l’annuaire Active Directory     |

***

#### <mark style="color:green;">🛠️ Exemple de chaîne de confiance avec CA racine et CA intermédiaire</mark>

* **CA Racine** émet un certificat pour une **CA Intermédiaire** (signé par sa propre clé privée).
* **CA Intermédiaire** signe un certificat pour un serveur web (par exemple, un certificat SSL/TLS).
* Le serveur web utilise ce certificat pour établir une connexion HTTPS sécurisée.
* Lorsqu'un navigateur ou un client interroge le serveur, il vérifie la chaîne de confiance :
  1. Le certificat du serveur est signé par la **CA intermédiaire**.
  2. La **CA intermédiaire** est signée par la **CA racine**, qui est préinstallée dans le magasin de certificats des systèmes de confiance (comme les navigateurs web).
  3. Si tout correspond, le certificat du serveur est validé comme étant digne de confiance.

***

{% hint style="info" %}
### <mark style="color:blue;">Structure technique d'un certificat</mark>

Un certificat X.509 contient plusieurs éléments clés :

**Données du certificat :**

* Version du format X.509
* Numéro de série unique
* Algorithme de signature (ex: SHA-256 with RSA)
* Nom de l'émetteur (CA qui a signé)
* Période de validité (dates début/fin)
* Nom du sujet (entité certifiée)
* Clé publique du sujet + algorithme
* Extensions (usage de la clé, contraintes, etc.)

**Signature numérique :**

* Empreinte (hash) des données ci-dessus
* Signature de cette empreinte par la clé privée de la CA

***

<mark style="color:green;">**Processus de signature "under the hood"**</mark>

**1. Création de la signature**

{% code overflow="wrap" %}
```
1. La CA prend toutes les données du certificat
2. Calcule un hash SHA-256 de ces données → H(données)
3. Chiffre ce hash avec sa clé privée RSA → Signature = RSA_privé(H(données))
4. Ajoute cette signature au certificat
```
{% endcode %}

2\. Vérification de la signature

{% code overflow="wrap" fullWidth="true" %}
```
1. Le client extrait la signature du certificat
2. Déchiffre la signature avec la clé publique de la CA → H_déchiffré = RSA_public(Signature)
3. Recalcule le hash des données du certificat → H_calculé = SHA-256(données)
4. Compare : H_déchiffré == H_calculé ?
   - Si OUI → signature valide
   - Si NON → certificat compromis/invalide
```
{% endcode %}

***

<mark style="color:green;">**Chaîne de confiance technique**</mark>

**CA Racine (Root CA)**

* **Auto-signée** : sa propre clé privée signe son propre certificat
* Clé privée ultra-sécurisée (souvent hors ligne, HSM)
* Certificat préinstallé dans les navigateurs/OS
* Durée de vie très longue (10-20 ans)

**CA Intermédiaire**

* Son certificat est signé par la CA racine
* Possède sa propre paire de clés (publique/privée)
* Signe les certificats des serveurs finaux
* Peut être révoquée sans affecter la CA racine

**Certificat serveur (end-entity)**

* Signé par la CA intermédiaire
* Contient la clé publique du serveur
* Utilisé pour l'authentification et le chiffrement

***

<mark style="color:green;">**Validation complète d'une chaîne**</mark>

Quand ton navigateur valide une chaîne HTTPS :

```
1. Récupère le certificat du serveur
2. Vérifie sa signature avec la clé publique de la CA intermédiaire
3. Récupère le certificat de la CA intermédiaire
4. Vérifie sa signature avec la clé publique de la CA racine
5. Vérifie que la CA racine est dans son magasin de confiance
6. Vérifie les dates de validité de tous les certificats
7. Vérifie que les certificats ne sont pas révoqués (CRL/OCSP)
```

***

<mark style="color:green;">**Exemple concret avec RSA**</mark>

```
CA Racine génère :
- Clé privée racine (2048 bits)
- Clé publique racine (2048 bits)
- Certificat auto-signé

CA Intermédiaire génère :
- Clé privée intermédiaire (2048 bits)
- Clé publique intermédiaire (2048 bits)
- Demande de certificat (CSR) avec sa clé publique

CA Racine :
- Prend les données du certificat intermédiaire
- Hash SHA-256 → 256 bits
- Signe avec RSA privé racine → 2048 bits de signature
- Émet le certificat intermédiaire signé
```

***

<mark style="color:green;">**Sécurité cryptographique**</mark>

La sécurité repose sur :

* **Intégrité** : hash détecte toute modification
* **Authenticité** : seule la CA avec la clé privée peut signer
* **Non-répudiation** : la CA ne peut nier avoir signé

Si quelqu'un modifie un certificat, le hash change et la signature devient invalide. Si quelqu'un essaie de créer un faux certificat, il ne peut pas le signer sans la clé privée de la CA.

C'est pourquoi les clés privées des CA sont si critiques et protégées par des mesures de sécurité extrêmes (HSM, multi-signatures, stockage hors ligne, etc.).
{% endhint %}

***

## <mark style="color:$danger;">Terminologie PKI</mark>

### <mark style="color:blue;">PKI (Infrastructure à Clés Publiques / Public Key Infrastructure)</mark>

**Définition :** Un système complet qui gère les certificats numériques et la cryptographie à clés publiques pour sécuriser les communications et authentifier les identités.

**Explication détaillée :** La PKI est comme un système de cartes d'identité numériques ultra-sécurisées. Imaginez que vous voulez prouver votre identité en ligne de manière absolument fiable - la PKI permet cela grâce à des certificats numériques qui fonctionnent comme des passeports électroniques.

<mark style="color:$success;">**Composants principaux d'une PKI :**</mark>

* **Autorités de certification (CA)** : Les "préfectures" qui délivrent les certificats
* **Autorités d'enregistrement (RA)** : Les "guichets" qui vérifient l'identité avant émission
* **Répertoires de certificats** : Les "bases de données" stockant les certificats publics
* **Systèmes de révocation** : Les "listes noires" des certificats annulés

<mark style="color:$success;">**Exemples concrets :**</mark>

* Navigation HTTPS sur un site web (le cadenas vert)
* Signature électronique de documents
* Authentification par carte à puce d'entreprise
* Chiffrement des emails avec S/MIME

***

### <mark style="color:blue;">AD CS (Services de Certificats Active Directory / Active Directory Certificate Services)</mark>

**Définition :** L'implémentation Microsoft de la PKI, intégrée à l'écosystème Active Directory de Windows.

**Explication détaillée :** AD CS est la solution PKI "maison" de Microsoft, parfaitement intégrée dans l'environnement Windows. C'est comme avoir sa propre "préfecture des certificats" directement dans son entreprise, qui connaît déjà tous les utilisateurs, ordinateurs et services de l'organisation via Active Directory.

<mark style="color:$success;">**Avantages spécifiques :**</mark>

* **Intégration native** : Utilise les comptes AD existants
* **Déploiement automatique** : Les certificats peuvent être distribués automatiquement via GPO (Group Policy Objects)
* **Gestion centralisée** : Administration via les outils Windows habituels
* **Templates prédéfinis** : Modèles de certificats prêts à l'emploi

**Cas d'usage typiques :**

* Certificats d'authentification pour les utilisateurs du domaine
* Certificats SSL/TLS pour les serveurs internes (IIS, Exchange)
* Certificats pour le chiffrement EFS (Encrypting File System)
* Certificats pour les réseaux Wi-Fi d'entreprise (802.1X)

***

### <mark style="color:blue;">CA (Autorité de Certification / Certificate Authority)</mark>

**Définition :** Le serveur PKI qui émet, valide et révoque les certificats numériques.

**Explication détaillée :** Une CA est comme un notaire numérique de confiance absolue. Son rôle est de vérifier l'identité des demandeurs et de délivrer des certificats qui attestent de cette identité. La confiance accordée à une CA est cruciale car elle se propage à tous les certificats qu'elle émet.

<mark style="color:$success;">**Types de CA :**</mark>

<mark style="color:orange;">**CA Racine (Root CA) :**</mark>

* La CA principale, au sommet de la hiérarchie
* Son certificat est auto-signé
* Doit être protégée au maximum (souvent hors ligne)
* **Exemple :** DigiCert, Let's Encrypt, VeriSign

#### <mark style="color:orange;">**CA Intermédiaire (Subordinate CA) :**</mark>

* Certifiée par une CA racine
* Effectue les opérations quotidiennes d'émission
* Peut être spécialisée par usage (SSL, code signing, etc.)

#### <mark style="color:orange;">**CA Publique vs CA Privée :**</mark>

* **Publique :** Reconnue par les navigateurs (ex: DigiCert pour les sites web publics)
* **Privée :** Interne à l'organisation (ex: CA d'entreprise pour les ressources internes)

<mark style="color:orange;">**Processus d'émission d'un certificat :**</mark>

1. Réception de la CSR (demande de certificat)
2. Vérification de l'identité du demandeur
3. Validation des informations fournies
4. Génération et signature du certificat
5. Publication du certificat délivré

***

### <mark style="color:blue;">Enterprise CA (CA d'Entreprise)</mark>

**Définition :** Une CA intégrée à Active Directory, par opposition à une CA autonome (Standalone CA).

**Explication détaillée :** Une Enterprise CA est comme une "préfecture locale" qui connaît parfaitement tous les habitants de sa ville (le domaine AD). Elle peut prendre des décisions automatiques car elle a accès à l'annuaire AD et peut vérifier instantanément les identités et permissions.

**Avantages par rapport à une Standalone CA :**

#### **Intégration AD native :**

* Utilise les comptes utilisateurs/ordinateurs AD existants
* Respecte les groupes de sécurité AD
* S'appuie sur l'authentification Kerberos

#### **Templates de certificats :**

* Modèles préconfigurés pour différents usages
* Permissions granulaires par groupe AD
* Auto-enrollment possible

#### **Publication automatique :**

* Certificats publiés dans l'annuaire AD
* Accessibles via LDAP
* Distribution automatique par GPO

**Exemple de déploiement :**

```
Domaine : entreprise.local
Enterprise CA : ca.entreprise.local
- Template "Utilisateur Standard" → Groupe "Employés"
- Template "Administrateur" → Groupe "Admins Systèmes"
- Template "Serveur Web" → Groupe "Administrateurs Serveurs"
```

***

### <mark style="color:blue;">Certificate Template (Modèle de Certificat)</mark>

{% hint style="warning" %}
**Définition :** Un ensemble de paramètres et de politiques qui définit le contenu et les caractéristiques des certificats émis par une Enterprise CA.
{% endhint %}

**Explication détaillée :** Un template est comme un "formulaire pré-rempli" qui standardise les types de certificats émis. Plutôt que de configurer chaque certificat individuellement, l'administrateur crée des modèles réutilisables adaptés à différents besoins.

**Composants d'un template :**

<mark style="color:orange;">**Paramètres techniques :**</mark>

* **Durée de validité** : 1 an, 2 ans, etc.
* **Taille de clé** : 2048 bits, 4096 bits
* **Algorithme de hachage** : SHA-256, SHA-384
* **Fournisseur cryptographique** : Microsoft Software KSP, Hardware KSP

<mark style="color:orange;">**Paramètres de sécurité :**</mark>

* **Permissions d'enrollment** : Qui peut demander ce type de certificat
* **Signature requise** : Manager, CA Administrator
* **Archivage de clé privée** : Oui/Non

<mark style="color:orange;">**Extensions du certificat :**</mark>

* **Key Usage** : Digital Signature, Key Encipherment
* **Enhanced Key Usage (EKU)** : Client Authentication, Server Authentication
* **Subject Alternative Name** : Email, DNS names, UPN

<mark style="color:green;">**Exemples de templates courants :**</mark>

**Template "User" (Utilisateur) :**

```
Usage : Authentification utilisateur, chiffrement email
Durée : 1 an
EKU : Client Authentication, Secure Email
Permissions : Tous les utilisateurs authentifiés
Auto-enrollment : Activé
```

**Template "Web Server" :**

```
Usage : Certificats SSL pour serveurs web
Durée : 2 ans  
EKU : Server Authentication
Permissions : Groupe "Web Administrators"
Subject Name : Fourni dans la demande
SAN : DNS names multiples autorisés
```

**Template "Code Signing" :**

```
Usage : Signature de code/applications
Durée : 3 ans
EKU : Code Signing
Permissions : Groupe "Developers"
Signature CA requise : Oui (validation manuelle)
Archivage clé privée : Non (sécurité)
```

***

### <mark style="color:blue;">CSR (Demande de Signature de Certificat / Certificate Signing Request)</mark>

**Définition :** Un message formaté envoyé à une CA pour demander l'émission d'un certificat signé numériquement.

**Explication détaillée :** Une CSR est comme un "dossier de candidature" pour obtenir un certificat. Elle contient toutes les informations nécessaires pour que la CA puisse créer le certificat : l'identité du demandeur, sa clé publique, et les caractéristiques souhaitées du certificat.

<mark style="color:green;">**Contenu d'une CSR :**</mark>

**Informations d'identité (Distinguished Name) :**

* **CN (Common Name)** : www.exemple.com, Jean Dupont
* **O (Organization)** : Nom de l'entreprise
* **OU (Organizational Unit)** : Service, département
* **L (Locality)** : Ville
* **ST (State)** : Région/État
* **C (Country)** : Code pays (FR, US, etc.)

**Informations cryptographiques :**

* **Clé publique** : La clé publique correspondant à la clé privée générée
* **Algorithme** : RSA, ECDSA, etc.
* **Taille de clé** : 2048, 3072, 4096 bits

**Extensions demandées :**

* **Subject Alternative Names (SAN)** : Noms alternatifs
* **Key Usage** : Utilisations prévues de la clé
* **Extended Key Usage** : Usages étendus spécifiques

<mark style="color:green;">**Exemple de génération CSR (OpenSSL) :**</mark>

```bash
# Génération clé privée + CSR
openssl req -new -newkey rsa:2048 -keyout server.key -out server.csr

# Informations demandées :
Country Name: FR
State: Ile-de-France  
City: Paris
Organization: Mon Entreprise SARL
Organizational Unit: IT Department
Common Name: www.monsite.fr
Email: admin@monsite.fr
```

**Processus complet :**

1. **Génération** : Création de la paire de clés et de la CSR
2. **Soumission** : Envoi de la CSR à la CA
3. **Validation** : Vérification de l'identité par la CA
4. **Émission** : La CA signe et retourne le certificat
5. **Installation** : Déploiement du certificat avec sa clé privée

***

### <mark style="color:blue;">EKU (Usage Étendu de Clé / Extended/Enhanced Key Usage)</mark>

**Définition :** Des identifiants d'objets (OID) qui définissent précisément comment un certificat peut être utilisé.

**Explication détaillée :** Les EKU sont comme des "tampons d'autorisation" sur un certificat qui spécifient exactement à quoi il peut servir. C'est un mécanisme de sécurité qui empêche l'usage détourné d'un certificat (par exemple, utiliser un certificat d'authentification client pour signer du code).

<mark style="color:green;">**EKU les plus courants :**</mark>

**Server Authentication (1.3.6.1.5.5.7.3.1) :**

* **Usage :** Certificats SSL/TLS pour serveurs web, mail, etc.
* **Exemple :** Certificats HTTPS des sites web
* **Validation :** Le navigateur vérifie cette EKU pour accepter le certificat

**Client Authentication (1.3.6.1.5.5.7.3.2) :**

* **Usage :** Authentification des clients (utilisateurs, machines)
* **Exemple :** Cartes à puce, certificats utilisateur pour VPN
* **Validation :** Le serveur vérifie cette EKU lors de l'authentification

**Code Signing (1.3.6.1.5.5.7.3.3) :**

* **Usage :** Signature d'applications, drivers, scripts
* **Exemple :** Signature des .exe, .msi, drivers Windows
* **Validation :** Windows vérifie cette EKU avant d'exécuter du code signé

**Secure Email (1.3.6.1.5.5.7.3.4) :**

* **Usage :** Chiffrement et signature d'emails (S/MIME)
* **Exemple :** Certificats Outlook pour emails chiffrés
* **Validation :** Client email vérifie cette EKU pour S/MIME

**Time Stamping (1.3.6.1.5.5.7.3.8) :**

* **Usage :** Horodatage cryptographique
* **Exemple :** Serveurs d'horodatage pour signatures durables
* **Validation :** Assure la validité temporelle des signatures

<mark style="color:green;">**Exemples concrets d'usage :**</mark>

**Certificat Serveur Web Multi-Usage :**

```
EKU incluses :
- Server Authentication → HTTPS
- Client Authentication → Authentification mutuelle TLS
Usage : Serveur web avec authentification client obligatoire
```

**Certificat Utilisateur Complet :**

```
EKU incluses :
- Client Authentication → Connexion domaine/VPN
- Secure Email → S/MIME Outlook  
- Encrypting File System → Chiffrement fichiers EFS
Usage : Certificat "tout-en-un" utilisateur entreprise
```

**Vérification des EKU :** Les applications vérifient systématiquement que le certificat présenté possède les bonnes EKU :

* **Navigateur web** : Vérifie "Server Authentication" pour HTTPS
* **Client VPN** : Vérifie "Client Authentication" pour l'utilisateur
* **Windows** : Vérifie "Code Signing" avant d'exécuter un programme signé

***

### <mark style="color:blue;">Application Policy (Politique d'Application)</mark>

**Définition :** Équivalent Windows des EKU, mais avec des options supplémentaires et une intégration plus poussée dans l'écosystème Microsoft.

**Explication détaillée :** Les Application Policies sont la version "Windows-centrée" des EKU standard. Microsoft a créé ce système pour avoir plus de contrôle et d'options spécifiques à Windows, tout en restant compatible avec les EKU standard. C'est comme avoir une "version étendue" des EKU avec des fonctionnalités bonus pour Windows.

<mark style="color:green;">**Différences avec les EKU standard :**</mark>

**Options supplémentaires :**

* **Contraintes d'usage plus fines** : Restrictions temporelles, géographiques
* **Intégration Group Policy** : Déploiement et contrôle centralisé
* **Validation renforcée** : Vérifications supplémentaires spécifiques Windows

<mark style="color:green;">**Policies spécifiques Microsoft :**</mark>

**Smart Card Logon (1.3.6.1.4.1.311.20.2.2) :**

* **Usage :** Authentification par carte à puce Windows
* **Spécificité :** Intégration native avec le login Windows
* **Exemple :** Cartes à puce employés pour ouverture session Windows

**Encrypting File System (1.3.6.1.4.1.311.10.3.4) :**

* **Usage :** Chiffrement de fichiers EFS natif Windows
* **Spécificité :** Intégration directe avec NTFS
* **Exemple :** Chiffrement transparent dossiers utilisateur

**Windows Update (1.3.6.1.4.1.311.76.6.1) :**

* **Usage :** Signature des mises à jour Windows
* **Spécificité :** Validation des packages Microsoft uniquement
* **Exemple :** Authentification des .msu, .cab de Windows Update

**BitLocker Drive Encryption (1.3.6.1.4.1.311.67.1.1) :**

* **Usage :** Gestion des clés BitLocker
* **Spécificité :** Intégration TPM et Active Directory
* **Exemple :** Récupération centralisée clés BitLocker



<mark style="color:green;">**Exemple de configuration avancée :**</mark>

**Certificat Administrateur Système :**

```
Application Policies incluses :
- Client Authentication → Authentification réseau
- Smart Card Logon → Connexion Windows  
- Encrypting File System → Chiffrement fichiers
- Remote Desktop Authentication → Bureau à distance

Contraintes spéciales :
- Durée de validité : 6 mois (renouvellement fréquent)
- Révocation automatique si compte AD désactivé
- Usage limité aux heures ouvrables (Group Policy)
- Logging renforcé de tous les usages
```

**Intégration Group Policy :**

```
Politique "Certificats Développeurs" :
- Application Policy : Code Signing uniquement
- Restriction : Signature limitée aux .exe internes
- Validation : Double signature requise (dev + manager)
- Audit : Log de toutes les signatures dans Event Log
- Distribution : Auto-deployment via GPO aux groupes autorisés
```

**Avantages dans l'écosystème Windows :**

* **Gestion centralisée** : Configuration via Group Policy Objects
* **Intégration AD native** : Respect automatique des groupes de sécurité
* **Audit renforcé** : Logging détaillé dans l'Event Log Windows
* **Révocation dynamique** : Synchronisation avec les changements AD
* **Validation contextuelle** : Vérifications selon le contexte d'usage (heure, lieu, etc.)
