# Directory & File Fuzzing

### <mark style="color:blue;">🔎 Objectif</mark>

Découvrir **répertoires, fichiers et endpoints cachés** d’une application web (backups, config, vieux scripts, panels admin, environnements de dev) qui peuvent divulguer des infos sensibles ou offrir des points d’entrée.

***

### <mark style="color:blue;">🧭 Pourquoi c’est important</mark>

* Permet d’identifier des **ressources non référencées** (fichiers .bak, config, logs).
* Ces ressources manquent souvent de protections et peuvent faciliter une compromission.
* Donne une vue complète de la **surface d’attaque** pour un audit ou pentest.

***

### <mark style="color:blue;">🧰 Méthode générale</mark>

1. Choisir / préparer une **wordlist** (liste de noms de dossiers/fichiers).
2. Lancer un outil de content discovery (ex. `ffuf`, `gobuster`, `feroxbuster`).
3. Analyser les **codes HTTP**, tailles et réponses textuelles pour repérer les ressources valides.
4. Affiner (extensions, chemins récursifs, exclusions) et **valider** manuellement les découvertes.

***

### <mark style="color:blue;">🔑 Wordlists (essentielles)</mark>

* **SecLists** (repository référence) — souvent installée sous `/usr/share/seclists/` sur les distro pentest.
  * `Discovery/Web-Content/common.txt` — bon démarrage général
  * `Discovery/Web-Content/directory-list-2.3-medium.txt` — liste medium pour dossiers
  * `Discovery/Web-Content/raft-large-directories.txt` — large, explorations profondes
  * `Discovery/Web-Content/big.txt` — très volumineuse (fais attention au temps)
* Astuce : adaptes les listes au contexte (CMS, WordPress, frameworks, langues).

***

### <mark style="color:blue;">⚙️ Exemple avec</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**ffuf**</mark> <mark style="color:blue;"></mark><mark style="color:blue;">(principes & flags courants)</mark>

#### <mark style="color:green;">Commande basique — directory fuzzing</mark>

{% code fullWidth="true" %}
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://IP:PORT/FUZZ
```
{% endcode %}

* `-w` : chemin du wordlist
* `-u` : URL, `FUZZ` = placeholder qui sera remplacé

#### <mark style="color:green;">Commande — file fuzzing avec extensions</mark>

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://IP:PORT/w2ksvrus/FUZZ -e .php,.html,.txt,.bak,.js -v
```

* `-e` : tester plusieurs extensions (.php, .html, ...)
* `-v` : verbose (plus d’info)

#### Interpréter la sortie

* **Status 200** → ressource trouvée (page valide).
* **Status 301/302** → redirection (peut indiquer un répertoire ou ressource déplacée).
* **Status 403** → accès refusé (possible ressource protégée mais existante).
* **Size / Words / Lines** : utile pour repérer résultats anormaux (ex. page très courte = possible fichier intéressant).
*   Exemple de résultat :

    ```
    dblclk.html [Status: 200, Size: 111] -> http://IP:PORT/w2ksvrus/dblclk.html
    ```

***

### <mark style="color:blue;">🧾 Fuzzing de fichiers — bonnes pratiques</mark>

* Teste des **extensions pertinentes** pour le site (ex: .php pour PHP, .aspx pour ASP.NET).
* Lance d’abord des listes **courtes** puis élargis si rien.
* Utilise des **threads** raisonnables (`-t`) pour ne pas DDoS la cible par erreur.
* Filtre les **faux positifs** (pages 404 custom avec code 200 — comparer size & pattern).
* Suis la **légalité / autorisation** : ne fuzz que des targets pour lesquels tu as la permission.

***

### <mark style="color:blue;">🛠️ Outils courants pour directory/file fuzzing</mark>

* `ffuf` (Go) — flexible, rapide, très utilisé pour dossiers/fichiers et paramètres.
* `gobuster` (Go) — simple & rapide pour découverte de contenu et vhosts.
* `feroxbuster` (Rust) — scans récursifs performants (forced browsing).
* `wfuzz` / `wenum` (Python) — puissant pour fuzz paramètres et custom payloads.

***

### <mark style="color:blue;">⚠️ Pièges & erreurs courantes</mark>

* **Custom 404** qui renvoie 200 → générer beaucoup de faux positifs : comparer `Size`/patterns.
* **Utiliser des wordlists trop grandes** sans ciblage → long & bruyant.
* **Ignorer redirections** : 301/302 peuvent indiquer panels ou URL finales importantes.
* **Ne pas vérifier manuellement** : toujours valider les découvertes via navigateur ou curl.

***

## <mark style="color:red;">Recursive Fuzzing</mark>

### <mark style="color:blue;">🎯 Objectif</mark>

Explorer automatiquement **les arborescences profondes** d’une appli web pour trouver des répertoires et fichiers cachés sans avoir à lancer manuellement chaque niveau.

***

### <mark style="color:blue;">🔁 Principe en 3 étapes</mark>

1. **Fuzz initial** : on lance le fuzzer sur la racine (ex. `http://IP:PORT/FUZZ`) avec une wordlist.
2. **Découverte & expansion** : quand un répertoire est trouvé (souvent `301`), le fuzzer crée une nouvelle branche `http://IP:PORT/dir/` et relance le fuzz sur `.../dir/FUZZ`.
3. **Itération** : répétition jusqu’à atteindre la profondeur maximale ou plus de nouveaux répertoires.

Image mentale : l’arbre dont la racine est `/`, chaque dossier découvert devient une nouvelle branche à explorer.

***

### <mark style="color:blue;">✅ Pourquoi l’utiliser</mark>

* **Efficacité** : automatise l’exploration de structures profondes.
* **Exhaustivité** : réduit le risque de rater du contenu non lié à la racine.
* **Gain de temps** : évite les manipulations manuelles répétitives.
* **Scalabilité** : utile sur de grands sites complexes.

***

### <mark style="color:blue;">🛠️ Exemple (ffuf) — options utiles</mark>

Commande de base (concept) :

{% code overflow="wrap" fullWidth="true" %}
```shellscript
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://94.237.52.235:32485/recursive_fuzz/FUZZ -e .html -recursion
```
{% endcode %}

Flags importants :

* `-recursion` : active l’exploration récursive.
* `-recursion-depth N` : limite la profondeur à N (ex: `-recursion-depth 2`).
* `-rate N` : limite le nombre de requêtes par seconde (ex: `-rate 500`).
* `-timeout X` : timeout des requêtes.
* `-ic` : ignore les lignes commentées (`#`) dans la wordlist.
* `-e .php,.html,.txt` : tester plusieurs extensions.
* `-t N` / `-threads` : nombre de threads (attention à la charge serveur).

***

### <mark style="color:blue;">🧾 Interprétation des résultats</mark>

* **301 / 302** → souvent un dossier (redirection vers `.../dir/`).
* **200** → fichier existant (page valide).
* **403** → ressource existante mais protégée (intéressant).
* **Size / Words / Lines** : trier par taille pour repérer anomalies / flags (fichiers courts contenant `HTB{...}`).

Exemple de sortie utile :

```
[Status: 301] http://IP:PORT/level1 -> ajoute job pour /level1/FUZZ
[Status: 200] http://IP:PORT/level1/index.html -> potentielle page intéressante
```

***

### <mark style="color:blue;">🧭 Stratégie pratique rapide</mark>

1. Lancer recursion sur `/recursive_fuzz/` avec `-recursion-depth 2` et un rate raisonnable.
2. Repérer les `301` → laisser ffuf créer les jobs.
3. Sur les branches avec `200`, relancer un fuzz ciblé (extensions, wordlists plus fines).
4. Trier résultats par `Status` puis `Size` pour isoler fichiers courts qui pourraient contenir la flag (`HTB{...}`).
5. Valider manuellement via navigateur ou `curl`.

***
