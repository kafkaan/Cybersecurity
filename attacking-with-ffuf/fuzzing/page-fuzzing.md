# Page Fuzzing

## <mark style="color:red;">Fuzzing de Pages Web (Page Fuzzing)</mark>

***

Nous allons explorer la manière de trouver des pages cachées dans un site web à l'aide de l'outil **ffuf** en exploitant des listes de mots (wordlists) et des mots-clés. Cela inclut le fuzzing d'extensions de fichiers et de noms de fichiers.

***

## <mark style="color:red;">**Fuzzing d'Extensions**</mark>

Dans l'exemple précédent, nous avions découvert un répertoire `/blog`, mais celui-ci renvoyait une page vide. Aucun lien ou page accessible n'était visible manuellement. Pour trouver des pages cachées, nous allons utiliser **ffuf** pour deviner les extensions utilisées sur ce site.

**Étapes :**

1. **Identifier le type de serveur web :**
   * Les types d'extensions (.html, .php, .aspx, etc.) peuvent parfois être déduits à partir des **en-têtes de réponse HTTP** ou du type de serveur (Apache, IIS, etc.).
2. **Utiliser ffuf pour fuzzing des extensions :**
   * Placer le mot-clé `FUZZ` là où l'extension serait, par exemple, `index.FUZZ`.
   * Utiliser une wordlist contenant les extensions courantes, comme celle disponible dans **SecLists**.

**Exemple de commande :**

{% code fullWidth="true" %}
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
```
{% endcode %}

**Explication des paramètres :**

* **`-w`** : Chemin vers la wordlist utilisée pour fuzzing.
* **`-u`** : URL cible avec le mot-clé `FUZZ` placé à l'endroit où se trouve l'extension.
* **`Matcher`** : Définit les codes de réponse HTTP que nous recherchons (200, 403, etc.).

***

#### **Résultat :**

```bash
.php                    [Status: 200, Size: 0, Words: 1, Lines: 1]
.phps                   [Status: 403, Size: 283, Words: 20, Lines: 10]
```

* **.php** renvoie un code 200, indiquant une réponse valide.
* Cela signifie que le site utilise probablement des pages PHP. Nous allons donc continuer avec cette extension.

***

## <mark style="color:red;">**Fuzzing de Noms de Fichiers**</mark>

Après avoir identifié que le site utilise des fichiers `.php`, nous allons utiliser une wordlist contenant des noms de fichiers communs pour trouver des fichiers cachés.

**Commande :**

{% code overflow="wrap" fullWidth="true" %}
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```
{% endcode %}

**Résultat :**

```bash
index                   [Status: 200, Size: 0, Words: 1, Lines: 1]
REDACTED                [Status: 200, Size: 465, Words: 42, Lines: 15]
```

* **index.php** : Page vide (taille 0).
* **REDACTED.php** : Page contenant du contenu. Celle-ci est intéressante à explorer.

***

#### **Conclusion :**

Le fuzzing nous permet de :

* Découvrir les extensions utilisées par le site web.
* Trouver des pages cachées grâce à des wordlists.

Ces techniques sont essentielles pour identifier des pages contenant potentiellement des données sensibles, comme des flags ou d'autres éléments exploitables.
