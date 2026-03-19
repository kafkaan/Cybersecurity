# PSPSY

***

### <mark style="color:red;">🧩 Définition</mark>

* **pspy** = _process snooping tool_ pour Linux.
* Permet de voir **les processus exécutés par tous les utilisateurs (y compris root)**, **sans privilèges spéciaux**.
* Très utilisé en **CTF / privesc** pour repérer :
  * Scripts cron root.
  * Services système qui relancent des binaires.
  * Commandes vulnérables exécutées automatiquement.

***

### <mark style="color:red;">🔐 Points forts</mark>

* Pas besoin de `root` ni de `ptrace`.
* Permet de "sniffer" en **temps réel** l’activité des processus.
* Détecte même des **commandes exécutées très brièvement** (ex: `ls` lancé par un script cron).
* Idéal dans des environnements restreints (pas de `strace`, pas de `auditd`).

***

### <mark style="color:red;">⚙️ Versions</mark>

* `pspy32` → pour systèmes 32 bits.
* `pspy64` → pour systèmes 64 bits (le plus utilisé en CTF modernes).

***

### <mark style="color:red;">📂 Lancement</mark>

Exécution basique :

```bash
./pspy64
```

Affichage type :

```
Config: Printing events...
Watching directories: [/usr /tmp /etc /home /var /opt]
2025/08/21 15:42:10 CMD: UID=0    PID=1234  | /usr/bin/cron -f
2025/08/21 15:42:10 CMD: UID=0    PID=1250  | /bin/sh -c /usr/local/bin/backup.sh
```

***

### <mark style="color:red;">🔎 Options utiles</mark>

#### <mark style="color:green;">1. Lister uniquement les commandes exécutées</mark>

```bash
./pspy64 -c
```

#### <mark style="color:green;">2. Limiter la profondeur de scan</mark>

```bash
./pspy64 -p 2
```

➡️ Moins bruyant, utile sur machines chargées.

#### <mark style="color:green;">3. Observer avec timestamps détaillés</mark>

```bash
./pspy64 -f
```

***

### <mark style="color:red;">🎯 Cas d’usage offensifs</mark>

#### <mark style="color:green;">1. Détection de cron jobs root</mark>

Exemple affichage :

```
2025/08/21 15:45:00 CMD: UID=0    PID=2314  | /bin/sh -c /usr/local/bin/cleanup.sh
```

➡️ `cleanup.sh` est exécuté par root → **cible idéale** pour privesc si écrivable.

***

#### <mark style="color:green;">2. Détection de services vulnérables</mark>

```
CMD: UID=0    PID=1542  | /usr/bin/python3 /opt/update.py
```

➡️ Si `/opt/update.py` est modifiable par toi → exécution root garantie.

***

#### <mark style="color:green;">3. Observation d’utilisateurs</mark>

```
CMD: UID=1001 PID=4321  | sshd: devuser@pts/1
```

➡️ Détecter si d’autres users se connectent (opportunité de credential hijacking).

***

#### 4. Monitoring discret

* Si tu suspectes un script `setuid` qui ne tourne que rarement.
* `pspy` permet de le **sniffer à l’instant exact** où il est lancé.

***

### <mark style="color:red;">📚 Exemple complet en CTF</mark>

1. Upload sur la cible :

```bash
scp pspy64 user@target:/tmp/pspy64
chmod +x /tmp/pspy64
```

2. Exécution :

```bash
./pspy64
```

3. Observation → tu vois un cron root :

```
CMD: UID=0 PID=876 | /bin/bash /opt/backup.sh
```

4. Vérification :

```bash
ls -l /opt/backup.sh
```

➡️ Si script modifiable par toi → **injection de payload root**.

***
