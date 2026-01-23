# Finding Files and Directories (CMD)

***

## <mark style="color:red;">🔍 Finding Files and Directories (CMD)</mark>

***

### <mark style="color:blue;">🧠 Pourquoi c’est critique ?</mark>

En situation réelle (attaque ou admin) :

* Les fichiers **ne sont pas là où on les attend**
* Les secrets sont **dissimulés**
* Les modifications doivent être **détectées rapidement**

👉 Savoir **chercher efficacement** fait souvent la différence.

***

## <mark style="color:blue;">🔎 Recherche de fichiers avec CMD</mark>

### 📌 1️⃣ La commande `where`

#### 🟢 À quoi sert `where` ?

* Trouver **l’emplacement exact** d’un fichier ou exécutable
* Fonctionne sur :
  * le **PATH** système
  * un chemin spécifique (avec `/R`)

***

#### 🔹 Recherche simple

```cmd
where calc.exe
```

➡️ Retourne le chemin car `System32` est dans le PATH

***

#### 🔹 Fichier non trouvé

```cmd
where bio.txt
```

❌ Rien trouvé → pas dans le PATH

***

#### 🔹 Recherche récursive (`/R`)

```cmd
where /R C:\Users\student\ bio.txt
```

📌 Recherche **dans tous les sous-dossiers**

***

#### 🔹 Recherche avec wildcard

```cmd
where /R C:\Users\student\ *.csv
```

📌 Utile pour :

* fichiers de logs
* exports
* listes d’IP
* bases de données légères

***

### <mark style="color:blue;">🧠 Cas d’usage Pentest</mark>

* Trouver des `.txt`, `.config`, `.ini`, `.csv`
* Localiser scripts ou binaires intéressants
* Identifier fichiers oubliés

***

## <mark style="color:red;">🧾 Recherche de contenu dans les fichiers</mark>

### <mark style="color:blue;">📌 2️⃣ La commande</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`find`</mark>

#### 🟢 À quoi sert `find` ?

* Chercher une **chaîne de caractères** dans un fichier
* Recherche **ligne par ligne**

***

#### 🔹 Recherche basique

```cmd
find "password" C:\Users\student\not-passwords.txt
```

➡️ Retourne les lignes contenant `password`

***

#### 🔹 Modificateurs utiles

| Option | Rôle                                         |
| ------ | -------------------------------------------- |
| `/I`   | Ignore la casse                              |
| `/N`   | Affiche numéros de ligne                     |
| `/V`   | Affiche lignes **ne contenant pas** le texte |

***

#### 🔹 Exemple avancé

```cmd
find /N /I /V "IP Address" example.txt
```

📌 Affiche :

* lignes sans “IP Address”
* insensibles à la casse
* avec numéros de ligne

***

#### ⚠️ Limite de `find`

❌ Pas de regex\
❌ Peu flexible

👉 Pour plus puissant → **findstr**

***

### <mark style="color:blue;">📌 3️⃣ La commande</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`findstr`</mark> <mark style="color:blue;"></mark><mark style="color:blue;">(grep de Windows)</mark>

#### 🟢 À quoi sert `findstr` ?

* Recherche **avancée**
* Supporte :
  * regex
  * patterns
  * wildcards
  * recherches multiples

💡 Équivalent Windows de `grep` sous Linux

***

#### 🔹 Exemple simple

```cmd
findstr "password" *.txt
```

***

#### 🔹 Regex (exemple)

```cmd
findstr /R "[Pp]ass(word)?" secrets.txt
```

***

#### 🔹 Recherche récursive

```cmd
findstr /S /I "password" C:\Users\
```

📌 **Très puissant pour la chasse aux secrets**

***

## <mark style="color:$danger;">⚖️ Comparer et analyser des fichiers</mark>

***

### <mark style="color:blue;">📌 4️⃣</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`comp`</mark> <mark style="color:blue;"></mark><mark style="color:blue;">— comparaison binaire</mark>

#### 🟢 À quoi sert `comp` ?

* Compare **byte par byte**
* Détecte toute modification

***

#### 🔹 Comparaison simple

```cmd
comp file-1.md file-2.md
```

***

#### 🔹 Comparaison ASCII

```cmd
comp file-1.md file-2.md /A
```

📌 Montre les caractères différents

***

#### 🔹 Résultat typique

```
Compare error at OFFSET 2
file1 = a
file2 = b
```

***

#### 🧠 Cas d’usage

* Détecter un binaire modifié
* Vérifier intégrité de scripts
* Identifier une altération malveillante

***

### <mark style="color:blue;">📌 5️⃣</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`fc`</mark> <mark style="color:blue;"></mark><mark style="color:blue;">— File Compare (plus lisible)</mark>

#### 🟢 Différence avec `comp`

* Compare **ligne par ligne**
* Sortie plus compréhensible
* Meilleur pour fichiers texte

***

#### 🔹 Exemple

```cmd
fc passwords.txt modded.txt /N
```

📌 Affiche :

* lignes modifiées
* numéros de lignes
* ajouts / suppressions

***

#### 🧠 Cas d’usage

* Comparer wordlists
* Vérifier fichiers de config
* Analyser logs

***

## <mark style="color:$danger;">🔢 Trier et nettoyer des données</mark>

### 📌 6️⃣ `sort`

#### 🟢 À quoi sert `sort` ?

* Trier des données
* Nettoyer des listes
* Préparer des comparaisons

***

#### 🔹 Trier un fichier

```cmd
sort file-1.md /O sorted.md
```

***

#### 🔹 Supprimer les doublons

```cmd
sort sorted.md /unique
```

📌 Très utile pour :

* listes d’IP
* utilisateurs
* chemins
* résultats d’énumération

***

### <mark style="color:blue;">🔄 Pipelines (important)</mark>

```cmd
type users.txt | sort | findstr admin
```

📌 Combine plusieurs outils = **énumération efficace**

***

## <mark style="color:red;">🧠 Résumé rapide</mark>

| Besoin                | Commande     |
| --------------------- | ------------ |
| Trouver fichier       | where        |
| Recherche récursive   | where /R     |
| Chercher texte simple | find         |
| Regex / patterns      | findstr      |
| Comparer fichiers     | comp / fc    |
| Trier données         | sort         |
| Supprimer doublons    | sort /unique |

***

## 📋 Tableau Récapitulatif Complet - Commandes CMD de Recherche et Analyse

<table data-full-width="true"><thead><tr><th>Commande</th><th width="273">Syntaxe Complète</th><th width="132">Paramètres</th><th>Explication des Paramètres</th><th>Exemple</th><th>Cas d'Usage</th></tr></thead><tbody><tr><td><strong>WHERE</strong></td><td><code>where &#x3C;fichier></code></td><td>Aucun</td><td>Recherche un fichier dans le PATH système uniquement</td><td><code>where calc.exe</code></td><td>Trouver l'emplacement d'un exécutable système</td></tr><tr><td><strong>WHERE</strong></td><td><code>where /R &#x3C;chemin> &#x3C;fichier></code></td><td><strong>/R</strong></td><td><strong>Recherche Récursive</strong> - Parcourt tous les sous-dossiers du chemin spécifié</td><td><code>where /R C:\Users\student\ bio.txt</code></td><td>Localiser un fichier spécifique dans toute une arborescence</td></tr><tr><td><strong>WHERE</strong></td><td><code>where /R &#x3C;chemin> &#x3C;pattern></code></td><td><strong>/R</strong> + <strong>wildcard</strong></td><td>Recherche récursive avec motif (*) pour trouver plusieurs fichiers correspondants</td><td><code>where /R C:\Users\ *.csv</code></td><td>Trouver tous les fichiers CSV, logs, ou exports dans un répertoire</td></tr><tr><td><strong>FIND</strong></td><td><code>find "texte" &#x3C;fichier></code></td><td>Aucun</td><td>Recherche une chaîne de caractères exacte, ligne par ligne (sensible à la casse)</td><td><code>find "password" secrets.txt</code></td><td>Trouver une chaîne précise dans un fichier</td></tr><tr><td><strong>FIND</strong></td><td><code>find /I "texte" &#x3C;fichier></code></td><td><strong>/I</strong></td><td><strong>Ignore la casse</strong> - Ne fait pas de différence entre majuscules et minuscules</td><td><code>find /I "Password" secrets.txt</code></td><td>Recherche insensible à la casse</td></tr><tr><td><strong>FIND</strong></td><td><code>find /N "texte" &#x3C;fichier></code></td><td><strong>/N</strong></td><td><strong>Numéros de ligne</strong> - Affiche le numéro de chaque ligne contenant le texte</td><td><code>find /N "admin" users.txt</code></td><td>Localiser précisément où se trouve l'information</td></tr><tr><td><strong>FIND</strong></td><td><code>find /V "texte" &#x3C;fichier></code></td><td><strong>/V</strong></td><td><strong>Inversion</strong> - Affiche les lignes qui NE contiennent PAS le texte recherché</td><td><code>find /V "IP Address" example.txt</code></td><td>Filtrer/exclure certaines lignes</td></tr><tr><td><strong>FIND</strong></td><td><code>find /I /N /V "texte" &#x3C;fichier></code></td><td><strong>/I /N /V</strong></td><td>Combinaison : ignore casse + numéros ligne + inversion</td><td><code>find /N /I /V "IP Address" example.txt</code></td><td>Recherche complexe avec plusieurs critères</td></tr><tr><td><strong>FINDSTR</strong></td><td><code>findstr "texte" &#x3C;fichier></code></td><td>Aucun</td><td>Recherche simple dans un fichier (plus puissant que find)</td><td><code>findstr "password" file.txt</code></td><td>Recherche basique améliorée</td></tr><tr><td><strong>FINDSTR</strong></td><td><code>findstr "texte" *.ext</code></td><td><strong>wildcard</strong></td><td>Recherche dans tous les fichiers d'une extension donnée</td><td><code>findstr "admin" *.txt</code></td><td>Scanner tous les fichiers d'un type</td></tr><tr><td><strong>FINDSTR</strong></td><td><code>findstr /I "texte" &#x3C;fichier></code></td><td><strong>/I</strong></td><td><strong>Ignore la casse</strong> - Insensible aux majuscules/minuscules</td><td><code>findstr /I "Password" secrets.txt</code></td><td>Recherche flexible sur la casse</td></tr><tr><td><strong>FINDSTR</strong></td><td><code>findstr /S "texte" &#x3C;chemin></code></td><td><strong>/S</strong></td><td><strong>Sous-dossiers</strong> - Recherche récursive dans toute l'arborescence</td><td><code>findstr /S "password" C:\Users\</code></td><td>Scan complet d'un répertoire</td></tr><tr><td><strong>FINDSTR</strong></td><td><code>findstr /R "regex" &#x3C;fichier></code></td><td><strong>/R</strong></td><td><strong>Expressions Régulières</strong> - Active les patterns regex pour recherches avancées</td><td><code>findstr /R "[Pp]ass(word)?" secrets.txt</code></td><td>Recherche avec patterns complexes</td></tr><tr><td><strong>FINDSTR</strong></td><td><code>findstr /S /I "texte" &#x3C;chemin></code></td><td><strong>/S /I</strong></td><td>Combinaison : récursif + ignore casse</td><td><code>findstr /S /I "password" C:\</code></td><td>Scan complet insensible à la casse</td></tr><tr><td><strong>FINDSTR</strong></td><td><code>findstr /N "texte" &#x3C;fichier></code></td><td><strong>/N</strong></td><td><strong>Numéros de ligne</strong> - Affiche les numéros de ligne</td><td><code>findstr /N "error" log.txt</code></td><td>Localiser précisément les erreurs</td></tr><tr><td><strong>FINDSTR</strong></td><td><code>findstr /M "texte" *.txt</code></td><td><strong>/M</strong></td><td><strong>Noms de fichiers seulement</strong> - Affiche uniquement les noms des fichiers contenant le texte</td><td><code>findstr /M "admin" *.log</code></td><td>Lister rapidement les fichiers concernés</td></tr><tr><td><strong>COMP</strong></td><td><code>comp &#x3C;fichier1> &#x3C;fichier2></code></td><td>Aucun</td><td>Compare deux fichiers <strong>byte par byte</strong> (comparaison binaire stricte)</td><td><code>comp file1.exe file2.exe</code></td><td>Détecter toute modification binaire</td></tr><tr><td><strong>COMP</strong></td><td><code>comp &#x3C;fichier1> &#x3C;fichier2> /A</code></td><td><strong>/A</strong></td><td><strong>ASCII</strong> - Affiche les différences en caractères ASCII lisibles</td><td><code>comp file1.txt file2.txt /A</code></td><td>Voir les différences de caractères</td></tr><tr><td><strong>COMP</strong></td><td><code>comp &#x3C;fichier1> &#x3C;fichier2> /N=&#x3C;n></code></td><td><strong>/N=nombre</strong></td><td>Limite la comparaison aux <strong>N premières lignes</strong></td><td><code>comp file1.md file2.md /N=10</code></td><td>Comparer seulement le début des fichiers</td></tr><tr><td><strong>COMP</strong></td><td><code>comp &#x3C;fichier1> &#x3C;fichier2> /L</code></td><td><strong>/L</strong></td><td><strong>Numéros de ligne</strong> - Affiche les numéros de ligne des différences</td><td><code>comp file1.txt file2.txt /L</code></td><td>Localiser précisément les différences</td></tr><tr><td><strong>FC</strong></td><td><code>fc &#x3C;fichier1> &#x3C;fichier2></code></td><td>Aucun</td><td>Compare deux fichiers <strong>ligne par ligne</strong> (plus lisible que comp)</td><td><code>fc passwords.txt backup.txt</code></td><td>Comparaison lisible de fichiers texte</td></tr><tr><td><strong>FC</strong></td><td><code>fc &#x3C;fichier1> &#x3C;fichier2> /N</code></td><td><strong>/N</strong></td><td><strong>Numéros de ligne</strong> - Affiche les numéros de ligne dans la comparaison</td><td><code>fc config1.ini config2.ini /N</code></td><td>Identifier précisément les lignes modifiées</td></tr><tr><td><strong>FC</strong></td><td><code>fc &#x3C;fichier1> &#x3C;fichier2> /C</code></td><td><strong>/C</strong></td><td><strong>Ignore la casse</strong> - Ne tient pas compte des majuscules/minuscules</td><td><code>fc file1.txt file2.txt /C</code></td><td>Comparaison insensible à la casse</td></tr><tr><td><strong>FC</strong></td><td><code>fc &#x3C;fichier1> &#x3C;fichier2> /W</code></td><td><strong>/W</strong></td><td><strong>Ignore espaces</strong> - Ignore les espaces blancs et tabulations</td><td><code>fc script1.ps1 script2.ps1 /W</code></td><td>Comparer la logique sans se soucier du formatage</td></tr><tr><td><strong>FC</strong></td><td><code>fc &#x3C;fichier1> &#x3C;fichier2> /LBn</code></td><td><strong>/LB=nombre</strong></td><td><strong>Buffer de lignes</strong> - Définit le nombre de lignes consécutives différentes à tolérer</td><td><code>fc log1.txt log2.txt /LB5</code></td><td>Comparaison avec tolérance de différences</td></tr><tr><td><strong>FC</strong></td><td><code>fc /B &#x3C;fichier1> &#x3C;fichier2></code></td><td><strong>/B</strong></td><td><strong>Binaire</strong> - Force la comparaison binaire byte par byte (comme comp)</td><td><code>fc /B file1.exe file2.exe</code></td><td>Comparaison binaire stricte</td></tr><tr><td><strong>SORT</strong></td><td><code>sort &#x3C;fichier></code></td><td>Aucun</td><td>Trie les lignes d'un fichier par ordre alphabétique croissant (A→Z)</td><td><code>sort users.txt</code></td><td>Organiser une liste</td></tr><tr><td><strong>SORT</strong></td><td><code>sort &#x3C;fichier> /O &#x3C;sortie></code></td><td><strong>/O=fichier</strong></td><td><strong>Output</strong> - Enregistre le résultat trié dans un fichier de sortie spécifié</td><td><code>sort data.txt /O sorted.txt</code></td><td>Sauvegarder le tri dans un fichier</td></tr><tr><td><strong>SORT</strong></td><td><code>sort &#x3C;fichier> /R</code></td><td><strong>/R</strong></td><td><strong>Reverse</strong> - Tri inversé, ordre décroissant (Z→A, 9→0)</td><td><code>sort scores.txt /R</code></td><td>Trier du plus grand au plus petit</td></tr><tr><td><strong>SORT</strong></td><td><code>sort &#x3C;fichier> /UNIQUE</code></td><td><strong>/UNIQUE</strong></td><td><strong>Supprime les doublons</strong> - Ne garde qu'une occurrence de chaque ligne identique</td><td><code>sort ips.txt /UNIQUE</code></td><td>Nettoyer une liste (IPs, users, etc.)</td></tr><tr><td><strong>SORT</strong></td><td><code>sort &#x3C;fichier> /+n</code></td><td><strong>/+nombre</strong></td><td><strong>Colonne de tri</strong> - Commence le tri à partir de la colonne n (séparateur = espace)</td><td><code>sort data.csv /+2</code></td><td>Trier selon une colonne spécifique</td></tr><tr><td><strong>SORT</strong></td><td><code>sort &#x3C;fichier> /M &#x3C;ko></code></td><td><strong>/M=mémoire</strong></td><td><strong>Mémoire</strong> - Définit la quantité de mémoire (en Ko) à utiliser pour le tri</td><td><code>sort bigfile.txt /M 1024</code></td><td>Optimiser le tri de gros fichiers</td></tr></tbody></table>

***

