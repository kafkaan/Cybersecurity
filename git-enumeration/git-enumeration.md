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
