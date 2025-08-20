---
description: https://medium.com/@mrbnf/password-attacks-passwd-shadow-opasswd-5963e1cc4777
---

# Passwd, Shadow & Opasswd

***

Les distributions basées sur Linux peuvent utiliser de **nombreux mécanismes d’authentification différents**.\
L’un des plus utilisés et standardisés est le système **PAM (Pluggable Authentication Modules)** — en français, **Modules d’Authentification Modulaires**.

Les modules utilisés dans ce cadre sont appelés **`pam_unix.so`** ou **`pam_unix2.so`**.\
Sur les distributions basées sur Debian (comme Ubuntu ou Kali), ces modules sont situés dans le répertoire suivant :\
📂 `/usr/lib/x86_64-linux-gnu/security/`

***

#### 📌 Rôle des modules PAM :

Ces modules gèrent :

* Les **informations utilisateur** (identifiants, UID, etc.)
* Les **authentifications** (login/mot de passe)
* Les **sessions utilisateur**
* Les **mots de passe courants et historiques**

Par exemple :\
Lorsque nous utilisons la commande `passwd` pour changer le mot de passe d’un compte utilisateur, **c’est PAM qui est invoqué en arrière-plan**.\
Ce dernier prend les précautions nécessaires (validation, chiffrement, stockage) et **modifie les fichiers système appropriés**.

***

#### 🔧 Fichiers système impliqués :

Le module `pam_unix.so` s’appuie sur les **APIs standardisées** des bibliothèques système pour lire et modifier les informations d’authentification.

Voici les **fichiers gérés et mis à jour** :

* `/etc/passwd` → stocke les comptes utilisateurs (non sensibles)
* `/etc/shadow` → stocke les mots de passe chiffrés (cryptés avec SHA-512, bcrypt, etc.)

***

#### 🧩 Autres modules PAM disponibles :

En plus de `pam_unix`, PAM peut utiliser d’autres modules spécialisés pour différentes sources d’authentification :

| Module            | Description                                      |
| ----------------- | ------------------------------------------------ |
| `pam_ldap.so`     | Authentification via un annuaire LDAP            |
| `pam_krb5.so`     | Intégration avec Kerberos (ex. environnement AD) |
| `pam_mount.so`    | Montage automatique de dossiers à la connexion   |
| `pam_tally2.so`   | Gestion des tentatives de connexion échouées     |
| `pam_faillock.so` | Verrouillage de compte après X échecs            |

***

#### 🧪 Astuce Pentester

Tu peux auditer les modules PAM utilisés pour chaque service dans les fichiers du dossier :\
📁 `/etc/pam.d/`

Par exemple, pour SSH :

```bash
cat /etc/pam.d/sshd
```

Tu verras les modules invoqués dans l’ordre.\
Exemple d'entrée typique :

```
auth    required    pam_unix.so
account required    pam_unix.so
session required    pam_unix.so
```

Cela te permet de **savoir où le contrôle d’accès est appliqué**, et quelles règles peuvent être **bypassées ou modifiées** (ex: pour persister avec un backdoor PAM).

***

### <mark style="color:blue;">Passwd File</mark>

The `/etc/passwd` file contains information about every existing user on the system and can be read by all users and services.&#x20;

Each entry in the `/etc/passwd` file identifies a user on the system. Each entry has seven fields containing a form of a database with information about the particular user, where a colon (`:`) separates the information. Accordingly, such an entry may look something like this:

<mark style="color:orange;">**Passwd Format**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th><th></th><th></th><th></th><th></th></tr></thead><tbody><tr><td><code>cry0l1t3</code></td><td><code>x</code></td><td><code>1000</code></td><td><code>1000</code></td><td><code>cry0l1t3,,,</code></td><td><code>/home/cry0l1t3</code></td><td><code>/bin/bash</code></td></tr><tr><td>Login name</td><td>Password info</td><td>UID</td><td>GUID</td><td>Full name/comments</td><td>Home directory</td><td>Shell</td></tr></tbody></table>

The most interesting field for us is the Password information field in this section because there can be different entries here. One of the rarest cases that we may find only on very old systems is the hash of the encrypted password in this field. Modern systems have the hash values stored in the `/etc/shadow` file, which we will come back to later. Nevertheless, `/etc/passwd` is readable system-wide, giving attackers the possibility to crack the passwords if hashes are stored here.

{% hint style="info" %}
Usually, we find the value `x` in this field, which means that the passwords are stored in an encrypted form in the `/etc/shadow` file. However, it can also be that the `/etc/passwd` file is writeable by mistake. This would allow us to clear this field for the user `root` so that the password info field is empty. This will cause the system not to send a password prompt when a user tries to log in as `root`.
{% endhint %}

<mark style="color:orange;">**Editing /etc/passwd - Before**</mark>

```shell-session
root:x:0:0:root:/root:/bin/bash
```

<mark style="color:orange;">**Editing /etc/passwd - After**</mark>

```shell-session
root::0:0:root:/root:/bin/bash
```

<mark style="color:orange;">**Root without Password**</mark>

```shell-session
[cry0l1t3@parrot]─[~]$ head -n 1 /etc/passwd

root::0:0:root:/root:/bin/bash


[cry0l1t3@parrot]─[~]$ su

[root@parrot]─[/home/cry0l1t3]#
```

Even though the cases shown will rarely occur, we should still pay attention and watch for security gaps because there are applications that require us to set specific permissions for entire folders. If the administrator has little experience with Linux or the applications and their dependencies, the administrator may give write permissions to the `/etc` directory and forget to correct them.

***

### <mark style="color:blue;">Shadow File</mark>

Since reading the password hash values can put the entire system in danger, the file `/etc/shadow` was developed, which has a similar format to `/etc/passwd` but is only responsible for passwords and their management. It contains all the password information for the created users. For example, if there is no entry in the `/etc/shadow` file for a user in `/etc/passwd`, the user is considered invalid. The `/etc/shadow` file is also only readable by users who have administrator rights. The format of this file is divided into `nine fields`:

<mark style="color:orange;">**Shadow Format**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th width="125"></th><th width="112"></th><th></th><th width="74"></th><th></th><th></th><th></th><th></th><th></th></tr></thead><tbody><tr><td><code>cry0l1t3</code></td><td><code>$6$wBRzy$...SNIP...x9cDWUxW1</code></td><td><code>18937</code></td><td><code>0</code></td><td><code>99999</code></td><td><code>7</code></td><td><code>:</code></td><td><code>:</code></td><td><code>:</code></td></tr><tr><td>Username</td><td>Encrypted password</td><td>Last PW change</td><td>Min. PW age</td><td>Max. PW age</td><td>Warning period</td><td>Inactivity period</td><td>Expiration date</td><td>Unused</td></tr></tbody></table>

<mark style="color:orange;">**Shadow File**</mark>

```shell-session
[cry0l1t3@parrot]─[~]$ sudo cat /etc/shadow

root:*:18747:0:99999:7:::
sys:!:18747:0:99999:7:::
...SNIP...
cry0l1t3:$6$wBRzy$...SNIP...x9cDWUxW1:18937:0:99999:7:::
```

If the password field contains a character, such as `!` or `*`, the user cannot log in with a Unix password. However, other authentication methods for logging in, such as Kerberos or key-based authentication, can still be used. The same case applies if the `encrypted password` field is empty. This means that no password is required for the login. However, it can lead to specific programs denying access to functions. The `encrypted password` also has a particular format by which we can also find out some information:

* `$<type>$<salt>$<hashed>`

As we can see here, the encrypted passwords are divided into three parts. The types of encryption allow us to distinguish between the following:

<mark style="color:orange;">**Algorithm Types**</mark>

* `$1$` – MD5
* `$2a$` – Blowfish
* `$2y$` – Eksblowfish
* `$5$` – SHA-256
* `$6$` – SHA-512

By default, the SHA-512 (`$6$`) encryption method is used on the latest Linux distributions. We will also find the other encryption methods that we can then try to crack on older systems. We will discuss how the cracking works in a bit.

***

### <mark style="color:blue;">Opasswd</mark>

The PAM library (`pam_unix.so`) can prevent reusing old passwords. The file where old passwords are stored is the <mark style="color:orange;">**`/etc/security/opasswd`**</mark>. Administrator/root permissions are also required to read the file if the permissions for this file have not been changed manually.

#### <mark style="color:green;">**Reading /etc/security/opasswd**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```

Looking at the contents of this file, we can see that it contains several entries for the user `cry0l1t3`, separated by a comma (`,`). Another critical point to pay attention to is the hashing type that has been used. This is because the `MD5` (`$1$`) algorithm is much easier to crack than SHA-512. This is especially important for identifying old passwords and maybe even their pattern because they are often used across several services or applications. We increase the probability of guessing the correct password many times over based on its pattern.

***

### <mark style="color:blue;">Cracking Linux Credentials</mark>

Once we have collected some hashes, we can try to crack them in different ways to get the passwords in cleartext.

<mark style="color:orange;">**Unshadow**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo cp /etc/passwd /tmp/passwd.bak 
mrroboteLiot@htb[/htb]$ sudo cp /etc/shadow /tmp/shadow.bak 
mrroboteLiot@htb[/htb]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

<mark style="color:orange;">**Hashcat - Cracking Unshadowed Hashes**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```
{% endcode %}

<mark style="color:orange;">**Hashcat - Cracking MD5 Hashes**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ cat md5-hashes.list

qNDkF0zJ3v8ylCOrKB0kt0
E9uMSmiQeRh4pAAgzuvkq1
```

```shell-session
mrroboteLiot@htb[/htb]$ hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```
