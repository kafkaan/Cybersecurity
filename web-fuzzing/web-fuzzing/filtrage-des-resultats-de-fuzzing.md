# Filtrage des Résultats de Fuzzing

### <mark style="color:blue;">🎯 Pourquoi Filtrer ?</mark>

Les outils de fuzzing génèrent **énormément de données**. Le filtrage permet de :

* ✅ Se concentrer sur les résultats pertinents
* ✅ Éliminer le bruit (erreurs 404, réponses vides, etc.)
* ✅ Accélérer l'analyse des vulnérabilités

***

### <mark style="color:blue;">🔧 Gobuster - Options de Filtrage</mark>

⚠️ **Attention** : Les options `-s` et `-b` sont **uniquement disponibles en mode `dir`**

| Flag               | Description                                       | Exemple d'Usage                                   |
| ------------------ | ------------------------------------------------- | ------------------------------------------------- |
| `-s` (include)     | Inclure uniquement les codes de statut spécifiés  | Chercher les redirections : `-s 301,302,307`      |
| `-b` (exclude)     | Exclure les codes de statut spécifiés             | Exclure les 404 : `-b 404`                        |
| `--exclude-length` | Exclure les réponses avec des tailles spécifiques | Ignorer les réponses vides : `--exclude-length 0` |

Exemple Pratique

```bash
# Trouver répertoires avec codes 200 ou 301, exclure réponses vides
gobuster dir -u http://example.com/ -w wordlist.txt -s 200,301 --exclude-length 0
```

***

### <mark style="color:blue;">🚀 FFUF - Système de Filtrage Avancé</mark>

#### <mark style="color:green;">Filtres par Code de Statut</mark>

| Flag                | Description                  | Exemple                               |
| ------------------- | ---------------------------- | ------------------------------------- |
| `-mc` (match code)  | Inclure uniquement ces codes | `-mc 200` → Seulement les succès      |
| `-fc` (filter code) | Exclure ces codes            | `-fc 404` → Supprimer les "Not Found" |

**Par défaut**, FFUF filtre : `200-299, 301, 302, 307, 401, 403, 405, 500`

#### <mark style="color:green;">Filtres par Taille</mark>

| Flag                | Description                    | Exemple                                                                     |
| ------------------- | ------------------------------ | --------------------------------------------------------------------------- |
| `-fs` (filter size) | Exclure tailles spécifiques    | `-fs 0` → Pas de réponses vides\<br>`-fs 100-200` → Exclure 100 à 200 bytes |
| `-ms` (match size)  | Inclure uniquement ces tailles | `-ms 3456` → Fichier de taille exacte                                       |

#### <mark style="color:green;">Filtres par Nombre de Mots</mark>

| Flag                 | Description            | Exemple                                    |
| -------------------- | ---------------------- | ------------------------------------------ |
| `-fw` (filter words) | Exclure nombre de mots | `-fw 219` → Filtrer réponses avec 219 mots |
| `-mw` (match words)  | Inclure nombre de mots | `-mw 5-10` → Messages de 5 à 10 mots       |

#### <mark style="color:green;">Filtres par Nombre de Lignes</mark>

| Flag                 | Description              | Exemple                                 |
| -------------------- | ------------------------ | --------------------------------------- |
| `-fl` (filter lines) | Exclure nombre de lignes | `-fl 10` → Retirer messages à 10 lignes |
| `-ml` (match lines)  | Inclure nombre de lignes | `-ml 20` → Isoler format à 20 lignes    |

#### <mark style="color:green;">Filtre par Temps de Réponse</mark>

| Flag               | Description                           | Exemple                       |
| ------------------ | ------------------------------------- | ----------------------------- |
| `-mt` (match time) | Filtrer par TTFB (Time To First Byte) | `-mt >500` → Réponses > 500ms |

#### <mark style="color:green;">📝 Exemples Combinés FFUF</mark>

```bash
# Code 200, 427 mots, taille > 500 bytes
mrrobotEliot_1@htb[/htb]$ ffuf -u http://example.com/FUZZ -w wordlist.txt -mc 200 -fw 427 -ms >500

# Filtrer codes 404, 401, 302
mrrobotEliot_1@htb[/htb]$ ffuf -u http://example.com/FUZZ -w wordlist.txt -fc 404,401,302

# Fichiers .bak entre 10KB et 100KB
mrrobotEliot_1@htb[/htb]$ ffuf -u http://example.com/FUZZ.bak -w wordlist.txt -fs 0-10239 -ms 10240-102400

# Endpoints lents (> 500ms)
mrrobotEliot_1@htb[/htb]$ ffuf -u http://example.com/FUZZ -w wordlist.txt -mt >500
```

***

### <mark style="color:blue;">⚡ wenum - Filtrage Robuste</mark>

#### <mark style="color:green;">Filtres par Code de Statut</mark>

| Flag               | Description                   | Exemple                           |
| ------------------ | ----------------------------- | --------------------------------- |
| `--hc` (hide code) | Masquer ces codes             | `--hc 400` → Cacher Bad Request   |
| `--sc` (show code) | Afficher uniquement ces codes | `--sc 200` → Seulement les succès |

#### <mark style="color:green;">Filtres par Taille/Longueur</mark>

| Flag                 | Description                | Exemple                              |
| -------------------- | -------------------------- | ------------------------------------ |
| `--hl` (hide length) | Masquer par nb de lignes   | `--hl 50` → Masquer longues réponses |
| `--sl` (show length) | Afficher par nb de lignes  | `--sl 10` → Réponses à 10 lignes     |
| `--hs` (hide size)   | Masquer par taille (bytes) | `--hs 10000` → Masquer > 10KB        |
| `--ss` (show size)   | Afficher par taille        | `--ss 3456` → Taille exacte          |

#### <mark style="color:green;">Filtres par Mots</mark>

| Flag               | Description             | Exemple                                |
| ------------------ | ----------------------- | -------------------------------------- |
| `--hw` (hide word) | Masquer par nb de mots  | `--hw 100` → Cacher réponses verbeuses |
| `--sw` (show word) | Afficher par nb de mots | `--sw 5-10` → Messages courts          |

#### <mark style="color:green;">Filtres par Regex</mark>

| Flag                | Description                                   | Exemple                           |
| ------------------- | --------------------------------------------- | --------------------------------- |
| `--hr` (hide regex) | Masquer si correspond à regex                 | `--hr "Internal Server Error"`    |
| `--sr` (show regex) | Afficher si correspond à regex                | `--sr "admin"` → Contient "admin" |
| `--filter`          | Filtre général (afficher)                     | `--filter "Login"`                |
| `--hard-filter`     | Filtre dur (masquer + pas de post-processing) | `--hard-filter "Login"`           |

#### <mark style="color:green;">📝 Exemples Combinés wenum</mark>

```bash
# Succès et redirections uniquement
mrrobotEliot_1@htb[/htb]$ wenum -w wordlist.txt --sc 200,301,302 -u https://example.com/FUZZ

# Masquer erreurs communes
mrrobotEliot_1@htb[/htb]$ wenum -w wordlist.txt --hc 404,400,500 -u https://example.com/FUZZ

# Messages courts (5-10 mots)
mrrobotEliot_1@htb[/htb]$ wenum -w wordlist.txt --sw 5-10 -u https://example.com/FUZZ

# Masquer gros fichiers
mrrobotEliot_1@htb[/htb]$ wenum -w wordlist.txt --hs 10000 -u https://example.com/FUZZ

# Chercher "admin" OU "password"
mrrobotEliot_1@htb[/htb]$ wenum -w wordlist.txt --sr "admin\|password" -u https://example.com/FUZZ
```

***

### <mark style="color:blue;">🦀 Feroxbuster - Filtrage Puissant</mark>

#### <mark style="color:green;">Filtres de Requête</mark>

| Flag          | Description                   | Exemple                |
| ------------- | ----------------------------- | ---------------------- |
| `--dont-scan` | Exclure URLs/patterns du scan | `--dont-scan /uploads` |

#### <mark style="color:green;">Filtres de Réponse</mark>

| Flag                  | Description                 | Exemple                                  |
| --------------------- | --------------------------- | ---------------------------------------- |
| `-S, --filter-size`   | Exclure par taille          | `-S 1024` → Exclure 1KB                  |
| `-X, --filter-regex`  | Exclure si regex correspond | `-X "Access Denied"`                     |
| `-W, --filter-words`  | Exclure par nb de mots      | `-W 0-10` → Éliminer messages courts     |
| `-N, --filter-lines`  | Exclure par nb de lignes    | `-N 50-` → Filtrer pages longues         |
| `-C, --filter-status` | Exclure codes (denylist)    | `-C 404,500` → Supprimer erreurs         |
| `--filter-similar-to` | Exclure pages similaires    | `--filter-similar-to error.html`         |
| `-s, --status-codes`  | Inclure codes (allowlist)   | `-s 200,204,301,302` → Succès uniquement |

#### <mark style="color:green;">📝 Exemple Combiné Feroxbuster</mark>

```bash
# Code 200, exclure > 10KB et contenant "error"
feroxbuster --url http://example.com -w wordlist.txt -s 200 -S 10240 -X "error"
```

***

### <mark style="color:blue;">🎓 Démonstration Pratique</mark>

```bash
mrrobotEliot_1@htb[/htb]$ ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -v -mc all
```

**Résultat** : Inondé de 404 NOT FOUND ! 😵

```
[Status: 404, Size: 36, Words: 4, Lines: 3] * FUZZ: .cache
[Status: 404, Size: 43, Words: 4, Lines: 3] * FUZZ: .bash_history
[Status: 404, Size: 34, Words: 4, Lines: 3] * FUZZ: .cvs
...
```

**Matcher par défaut** : `200-299,301,302,307,401,403,405,500`

{% code overflow="wrap" %}
```bash
mrrobotEliot_1@htb[/htb]$ ffuf -u http://83.136.250.108:31587/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -v
```
{% endcode %}

**Résultat** : Seulement les réponses pertinentes ! ✅

***

### <mark style="color:blue;">🎯 Tableau Comparatif Rapide</mark>

| Besoin                | Gobuster             | FFUF       | wenum            | Feroxbuster    |
| --------------------- | -------------------- | ---------- | ---------------- | -------------- |
| **Exclure code 404**  | `-b 404`             | `-fc 404`  | `--hc 404`       | `-C 404`       |
| **Inclure code 200**  | `-s 200`             | `-mc 200`  | `--sc 200`       | `-s 200`       |
| **Exclure taille 0**  | `--exclude-length 0` | `-fs 0`    | `--hs 0`         | `-S 0`         |
| **Filtrer par regex** | ❌                    | ❌          | `--hr "pattern"` | `-X "pattern"` |
| **Filtrer par mots**  | ❌                    | `-fw N`    | `--hw N`         | `-W N`         |
| **Filtrer par temps** | ❌                    | `-mt >500` | ❌                | ❌              |

***
