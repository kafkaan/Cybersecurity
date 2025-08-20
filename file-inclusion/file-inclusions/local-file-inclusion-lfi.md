# Local File Inclusion (LFI)

***

### <mark style="color:red;">Basic LFI</mark>

1️⃣ **Fonctionnalité de l'application**

* L'application permet aux utilisateurs de choisir une langue (anglais ou espagnol).
* Lorsqu'on sélectionne une langue, le texte s'affiche dans la langue correspondante.

2️⃣ **Analyse du paramètre dans l'URL**

* La langue sélectionnée est transmise via un paramètre dans l'URL (ex: `es.php`).
* Le changement de langue peut être géré de différentes manières :
  * Chargement depuis une base de données spécifique.
  * Utilisation de fichiers distincts pour chaque langue.
  * Utilisation d'un moteur de template.

3️⃣ **Potentielle vulnérabilité LFI (Local File Inclusion)**

* Si l'application inclut directement un fichier basé sur le paramètre d'URL sans validation, il peut être manipulé.
* Un attaquant pourrait modifier `es.php` par un fichier système comme `/etc/passwd` (Linux) ou `C:\Windows\boot.ini` (Windows).
* Cela pourrait permettre l'affichage du contenu de fichiers sensibles sur le serveur.

4️⃣ **Démonstration de l'attaque**

* Tester si la vulnérabilité est exploitable en remplaçant `es` par `/etc/passwd`.
* Si le serveur affiche le fichier demandé, l'application est vulnérable au LFI.

<figure><img src="https://academy.hackthebox.com/storage/modules/23/basic_lfi_lang_passwd.png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">Path Traversal</mark>

***

Dans l'exemple précédent, nous avons lu un fichier en spécifiant son chemin absolu (par exemple : `/etc/passwd`). Cela fonctionne si l'entrée utilisateur est utilisée **telle quelle** dans la fonction `include()`, **sans être modifiée**, comme dans l'exemple suivant :

```php
include($_GET['language']);
```

Dans ce cas, si nous essayons de lire `/etc/passwd`, alors la fonction `include()` va directement tenter d'inclure ce fichier.

Cependant, **dans de nombreux cas**, les développeurs web ajoutent une chaîne de caractères **avant ou après** le paramètre `language`. Par exemple, le paramètre `language` peut être utilisé pour composer un nom de fichier dans un sous-dossier spécifique :

```php
include("./languages/" . $_GET['language']);
```

Dans ce cas, si nous essayons d'accéder à `/etc/passwd`, le chemin complet passé à `include()` devient :

```bash
./languages//etc/passwd
```

Comme ce fichier **n'existe pas dans ce répertoire**, on ne pourra pas le lire. Comme prévu, l’erreur affichée en mode **verbeux** nous indique que le fichier `/etc/passwd` n’existe pas dans le dossier `languages`.

***

#### 📌 Contournement par Traversée de Répertoires (Directory Traversal)

On peut facilement **bypasser cette restriction** en utilisant une **traversée de répertoire** via des chemins relatifs. Pour cela, on ajoute des `../` avant le nom du fichier ciblé. Le `../` permet de remonter dans l’arborescence, vers le dossier parent.

**Exemple** :\
Si le chemin complet du dossier `languages` est `/var/www/html/languages/`, alors :

```bash
../index.php
```

va référencer le fichier `index.php` situé dans le dossier parent, soit :

```bash
/var/www/html/index.php
```

On peut donc utiliser cette astuce pour **remonter l'arborescence** jusqu'à la racine (`/`), puis spécifier un chemin absolu comme :

```bash
../../../../etc/passwd
```

Et dans ce cas, si le fichier existe, il sera bien inclus.

***

#### 💡 Astuce d’optimisation

Il est **toujours préférable** d’être efficace et de **ne pas ajouter plus de `../` que nécessaire**, notamment lors de la rédaction d’un rapport ou lors de l’écriture d’un exploit. Essayez donc de **calculer précisément** combien de niveaux vous devez remonter.

> Exemple :\
> Avec un chemin comme `/var/www/html/`, nous sommes à **3 répertoires** de la racine.\
> Donc on utilisera :

```bash
../../../
```

Ce qui permet ensuite de référencer un fichier comme `/etc/passwd` de la manière suivante :

```bash
../../../etc/passwd
```

***

#### 🔒 À retenir pour les tests :

* Cette vulnérabilité est une **Local File Inclusion (LFI)** si elle permet d’inclure des fichiers locaux arbitraires.
* Elle peut mener à **Remote Code Execution (RCE)** si vous parvenez à inclure un fichier que vous avez pu uploader (ex : un fichier `.php` mal filtré).
* Très souvent présente dans les CMS ou frameworks custom mal protégés.

***

### <mark style="color:red;">Filename Prefix</mark>

***

Dans l'exemple précédent, nous avons utilisé le paramètre `language` **après** un répertoire, ce qui nous permettait d'utiliser une **traversée de répertoires** pour lire un fichier comme `/etc/passwd`.

Cependant, dans certaines situations, notre entrée peut être **ajoutée après une chaîne de caractères fixe (préfixe)**. Par exemple, elle peut être utilisée pour former un nom de fichier avec un préfixe, comme dans cet exemple :

```php
include("lang_" . $_GET['language']);
```

Dans ce cas, si nous essayons d’utiliser une traversée comme :

```bash
../../../etc/passwd
```

Le chemin final devient :

```bash
lang_../../../etc/passwd
```

Ce chemin est invalide car le système va chercher un fichier nommé **littéralement** `lang_../../../etc/passwd`, qui n’existe évidemment pas.

Comme attendu, l'erreur retournée indique que ce fichier n'existe pas.

***

#### 🧠 Bypass possible avec un `/` préfixé

Pour contourner ce problème, **au lieu d'utiliser directement la traversée de répertoires**, on peut tenter de **préfixer notre charge utile (payload) avec un `/`**.

Exemple de payload :

```bash
/../../../etc/passwd
```

Ce qui donnerait en sortie :

```bash
lang_/../../../etc/passwd
```

Ici, la chaîne `lang_` est traitée comme un **répertoire**, et le système va tenter de monter dans l’arborescence **à partir de ce répertoire**. Si les droits et chemins le permettent, cela peut fonctionner et on peut lire un fichier arbitraire.

***

#### ⚠️ Limitations & Remarques Importantes

* Ce contournement **ne fonctionne pas toujours**.
* Dans notre exemple, `lang_/` est considéré comme un dossier. **S’il n’existe pas**, la traversée de chemin relative échouera.
* Tout **préfixe** ajouté à notre entrée peut **casser certaines techniques classiques de LFI**, notamment :
  * les wrappers PHP (`php://filter`, `php://input`, `data://`, etc.)
  * les inclusions distantes (`RFI` – _Remote File Inclusion_), si activées (rare avec `allow_url_include=On`).
* Cela peut également rendre plus difficile l'exploitation avec des **fichiers uploadés** ou des **injections indirectes** via LFI à RCE (comme avec `log poisoning` ou `/proc/self/environ`).

***

### <mark style="color:red;">Appended Extensions</mark>

Another very common example is when an extension is appended to the `language` parameter, as follows:

```php
include($_GET['language'] . ".php");
```

This is quite common, as in this case, we would not have to write the extension every time we need to change the language. This may also be safer as it may restrict us to only including PHP files. In this case, if we try to read `/etc/passwd`, then the file included would be `/etc/passwd.php`, which does not exist:

There are several techniques that we can use to bypass this, and we will discuss them in upcoming sections.

***

### <mark style="color:red;">Second-Order Attacks</mark>

Les attaques LFI peuvent prendre différentes formes, dont l'attaque de **Second Order**. Cette méthode consiste à exploiter des fonctionnalités d'une application web qui récupèrent des fichiers sur le serveur à partir de paramètres contrôlés par l'utilisateur. Par exemple, un utilisateur malveillant peut enregistrer un nom d'utilisateur contenant un chemin LFI (comme `../../../etc/passwd`). Si l'application utilise ce nom d'utilisateur pour générer une URL (ex : `/profile/$username/avatar.png`), cela peut permettre de lire un fichier sensible au lieu d'afficher un avatar.

Cette technique repose sur l'injection d'une charge utile LFI dans une entrée stockée (ex : base de données), exploitée ensuite par une autre fonctionnalité. Les développeurs négligent souvent ce risque, car ils protègent les entrées directes mais font confiance aux données extraites de leur propre système.

***

## <mark style="color:red;">Basic Bypasses</mark>

***

### <mark style="color:blue;">Non-Recursive Path Traversal Filters</mark>

One of the most basic filters against LFI is a search and replace filter, where it simply deletes substrings of (`../`) to avoid path traversals. For example:

```php
$language = str_replace('../', '', $_GET['language']);
```

The above code is supposed to prevent path traversal, and hence renders LFI useless. If we try the LFI payloads we tried in the previous section, we get Erreur

{% hint style="danger" %}
We see that all `../` substrings were removed, which resulted in a final path being `./languages/etc/passwd`. However, this filter is very insecure, as it is not `recursively removing` the `../` substring, as it runs a single time on the input string and does not apply the filter on the output string. For example, if we use `....//` as our payload, then the filter would remove `../` and the output string would be `../`, which means we may still perform path traversal. Let's try applying this logic to include `/etc/passwd` again:
{% endhint %}

As we can see, the inclusion was successful this time, and we're able to read `/etc/passwd` successfully. The `....//` substring is not the only bypass we can use, as we may use `..././` or `....\/` and several other recursive LFI payloads. Furthermore, in some cases, escaping the forward slash character may also work to avoid path traversal filters (e.g. `....\/`), or adding extra forward slashes (e.g. `....////`)

***

### <mark style="color:red;">Encoding</mark>

Some web filters may prevent input filters that include certain LFI-related characters, like a dot `.` or a slash `/` used for path traversals. However, some of these filters may be bypassed by URL encoding our input, such that it would no longer include these bad characters, but would still be decoded back to our path traversal string once it reaches the vulnerable function. Core PHP filters on versions 5.3.4 and earlier were specifically vulnerable to this bypass, but even on newer versions we may find custom filters that may be bypassed through URL encoding.

If the target web application did not allow `.` and `/` in our input, we can URL encode `../` into `%2e%2e%2f`, which may bypass the filter. To do so, we can use any online URL encoder utility or use the Burp Suite Decoder tool, as follows:&#x20;

<figure><img src="../../.gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

Note: For this to work we must URL encode all characters, including the dots. Some URL encoders may not encode dots as they are considered to be part of the URL scheme.

***

### <mark style="color:red;">Approved Paths</mark>

Some web applications may also use Regular Expressions to ensure that the file being included is under a specific path. For example, the web application we have been dealing with may only accept paths that are under the `./languages` directory, as follows:

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

To find the approved path, we can examine the requests sent by the existing forms, and see what path they use for the normal web functionality. Furthermore, we can fuzz web directories under the same path, and try different ones until we get a match. To bypass this, we may use path traversal and start our payload with the approved path, and then use `../` to go back to the root directory and read the file we specify, as follows:

Some web applications may apply this filter along with one of the earlier filters, so we may combine both techniques by starting our payload with the approved path, and then URL encode our payload or use recursive payload.

Note: All techniques mentioned so far should work with any LFI vulnerability, regardless of the back-end development language or framework.

***

### <mark style="color:red;">Appended Extension</mark>

<mark style="color:green;">**1️⃣ Extension forcée (.php)**</mark>

* Certaines applications ajoutent automatiquement `.php` à l’input utilisateur pour s’assurer que seul du code PHP est inclus.
* Avec les versions modernes de PHP, il est difficile de contourner cela.
* Cependant, cela peut quand même être utile pour lire du code source d’un fichier.

***

<mark style="color:green;">**2️⃣ Troncature de chemin (Path Truncation) – Obsolète**</mark>

✅ **Principe**

* Dans les anciennes versions de PHP (≤ 5.3/5.4), les chaînes étaient limitées à **4096 caractères**.
* Tout ce qui dépassait cette limite était **coupé** (y compris `.php` si elle était trop loin).
* PHP supprimait aussi les **barres obliques finales** et les **points seuls** (`.`) dans un chemin.
* Exemple : `/etc/passwd/.` devenait `/etc/passwd`.

✅ **Exploitation**

* En créant un chemin **extrêmement long** avec beaucoup de `./`, on pouvait dépasser la limite et **supprimer automatiquement l’extension `.php`** ajoutée par l’application.

✅ **Payload d’exemple**

{% code fullWidth="true" %}
```bash
?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
```
{% endcode %}

Pour générer automatiquement cette chaîne :

{% code overflow="wrap" fullWidth="true" %}
```bash
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```
{% endcode %}

Sortie :

{% code fullWidth="true" %}
```
non_existing_directory/../../../etc/passwd/./././<SNIP>././././
```
{% endcode %}

🔥 **Remarque :**\
Si on ajoute trop de `../`, on reste quand même dans le répertoire `/`, mais il faut **bien calculer la longueur du chemin** pour s’assurer que **seule** `.php` est tronquée et pas notre fichier cible (`/etc/passwd`).

***

<mark style="color:green;">**3️⃣ Injection de Null Byte (%00) – Obsolète**</mark>

✅ **Principe**

* Avant **PHP 5.5**, il était possible d’injecter un **null byte** (`%00`) pour **tronquer un chemin**.
* En mémoire, une chaîne de caractères s’arrête au premier `\0` (null byte), comme en **C/C++**.

✅ **Exploitation**

* On ajoute `%00` à la fin du fichier demandé, ce qui **bloque** tout ce qui suit.
*   Exemple :

    ```bash
    ?language=/etc/passwd%00
    ```
* L’application voit `/etc/passwd%00.php`, mais PHP coupe après `%00` et charge `/etc/passwd`.

🚀 **Impact**

* Contournement direct des restrictions d’extension `.php`.
* Possibilité de lire des fichiers système sensibles (`/etc/passwd`, `/var/www/config.php`…).

***

## <mark style="color:red;">Filtres PHP</mark>&#x20;

Les applications web développées en PHP (comme celles utilisant Laravel ou Symfony) peuvent être vulnérables à des attaques LFI. Dans ce contexte, les **PHP Wrappers** permettent d'accéder à divers flux d'E/S au niveau de l'application, tels que les fichiers locaux ou les entrées/sorties standard. En tant que pentesteurs, ces fonctionnalités peuvent être exploitées pour lire des fichiers source en PHP ou exécuter des commandes système.

***

#### <mark style="color:green;">Utilisation des Filtres PHP</mark>

Les **filtres PHP** (comme `php://filter/`) permettent d'appliquer des transformations sur les fichiers inclus via une LFI. Le filtre le plus utile pour lire le code source d'un fichier PHP est **`convert.base64-encode`**, qui encode le contenu en Base64 au lieu d'exécuter le fichier.

**Exemple :**

Pour lire le code source d’un fichier comme `config.php`, on peut inclure le fichier via une URL en spécifiant le filtre Base64 :

{% code overflow="wrap" fullWidth="true" %}
```
http://<IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=config
```
{% endcode %}

Résultat : Au lieu de voir une page vide (car le fichier s'exécute normalement), on obtient une chaîne Base64 encodée. Cette chaîne peut être décodée avec une commande comme :

```bash
echo 'PD9waHAK...SNIP...' | base64 -d
```

Cela révèle le contenu source du fichier, où des informations sensibles comme des identifiants ou des clés de base de données peuvent être trouvées.

***

#### <mark style="color:green;">Recherche des Fichiers PHP à Lire</mark>

Pour maximiser l'exploitation, on peut utiliser des outils comme **ffuf** ou **gobuster** pour rechercher les fichiers PHP accessibles sur le serveur. Ces outils identifient des fichiers tels que `index.php`, `config.php`, ou d'autres qui peuvent contenir des informations utiles.

**Exemple de commande :**

{% code overflow="wrap" fullWidth="true" %}
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
```
{% endcode %}

Même les fichiers avec des codes de réponse HTTP comme `301`, `302` ou `403` peuvent être inclus pour extraire leur contenu source.

***
