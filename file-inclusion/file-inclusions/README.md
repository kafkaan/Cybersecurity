# File Inclusions

***

## <mark style="color:red;">**Inclusion Locale de Fichier (LFI)**</mark>

:page\_with\_curl: Le lieu le plus courant où l’on trouve des vulnérabilités LFI est souvent les moteurs de templates.&#x20;

:motor\_scooter: Ces moteurs affichent une page avec des parties statiques communes (comme l'en-tête, la barre de navigation et le pied de page) tout en chargeant dynamiquement d'autres contenus qui changent entre les pages. Cela permet d'éviter de devoir modifier toutes les pages du serveur lorsqu'une partie statique est mise à jour.

Par exemple, on peut souvent voir un paramètre tel que `/index.php?page=about`, où `index.php` affiche les parties statiques et charge ensuite le contenu dynamique spécifié dans le paramètre. Dans cet exemple, le contenu dynamique peut être lu depuis un fichier appelé `about.php`. Si l'on contrôle la valeur du paramètre `page`, il peut être possible de manipuler l'application web pour qu'elle récupère et affiche d'autres fichiers du serveur.

{% hint style="danger" %}
<mark style="color:green;">**Impact des LFI :**</mark>

1. **Divulgation du code source :** Les attaquants peuvent analyser le code pour y détecter d'autres failles, augmentant ainsi les risques.
2. **Exposition de données sensibles :** Des informations sensibles peuvent être récupérées, permettant à l'attaquant d'exploiter d'autres faiblesses ou d'accéder directement au serveur.
3. **Exécution de code à distance :** Dans des cas spécifiques, un LFI peut permettre de compromettre entièrement le serveur et les autres systèmes connectés.
{% endhint %}

***

## <mark style="color:red;">**Exemples de Code Vulnérable**</mark>

Les vulnérabilités d'inclusion de fichiers peuvent apparaître dans de nombreux langages et serveurs web populaires, comme PHP, NodeJS, Java, .NET, etc. Bien que chaque technologie ait une manière légèrement différente d’inclure des fichiers, elles partagent un point commun : charger un fichier à partir d’un chemin spécifié.

Un exemple courant est l’utilisation d’un paramètre HTTP (comme `language`) pour charger un fichier dynamique, souvent dans le cadre de la gestion des langues. Par exemple :

* Un paramètre GET `?language=fr` peut indiquer à l’application de charger un fichier depuis un répertoire spécifique (par exemple `/fr/`).
* Si le chemin est sous notre contrôle, il peut être exploité pour accéder à d'autres fichiers.

***

<mark style="color:green;">**Exemple avec PHP**</mark>

En PHP, la fonction **`include()`** permet de charger un fichier local ou distant. Si le chemin passé à **`include()`** provient d'un paramètre contrôlé par l'utilisateur et que l'entrée n'est pas filtrée ou validée, cela rend le code vulnérable à une inclusion de fichier.

Exemple de code vulnérable :

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

Dans cet exemple, tout chemin passé via le paramètre `language` sera inclus dans la page, y compris des fichiers locaux du serveur. Cela ne se limite pas à la fonction `include()` : d'autres fonctions comme <mark style="color:orange;">**`include_once()`**</mark><mark style="color:orange;">**,**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`require()`**</mark><mark style="color:orange;">**,**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`require_once()`**</mark><mark style="color:orange;">**, et même**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`file_get_contents()`**</mark> peuvent être vulnérables si elles reçoivent des paramètres non sécurisés.

***

<mark style="color:green;">**Exemple avec NodeJS**</mark>

Les serveurs NodeJS peuvent également charger des fichiers basés sur un paramètre HTTP. Exemple :

```javascript
if (req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```

Ici, le paramètre passé dans l'URL (`req.query.language`) est utilisé par la fonction `readFile` pour lire un fichier et afficher son contenu dans la réponse HTTP.

Autre exemple avec le framework **Express.js** :

```javascript
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```

Dans cet exemple, le paramètre `language` est directement utilisé pour déterminer le fichier à rendre.

***

<mark style="color:green;">**Exemple avec Java**</mark>

Les applications Java peuvent inclure des fichiers locaux via des paramètres comme dans les exemples ci-dessous :

Utilisation de la fonction `include` :

```jsp
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

Utilisation de la fonction `import` :

```jsp
<c:import url= "<%= request.getParameter('language') %>"/>
```

***

<mark style="color:green;">**Exemple avec .NET**</mark>

Les applications .NET peuvent présenter des vulnérabilités similaires. Par exemple :

```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```

Autre exemple avec la fonction `@Html.Partial()` :

```cs
@Html.Partial(HttpContext.Request.Query['language'])
```

***

## <mark style="color:red;">**Lire vs Exécuter**</mark>

{% hint style="warning" %}
Certaines fonctions lisent uniquement le contenu des fichiers, tandis que d'autres peuvent également les exécuter. Par exemple :

* `include()` en PHP peut exécuter un fichier s'il contient du code.
* En revanche, `file_get_contents()` ne fait que lire le contenu.
{% endhint %}

Voici un tableau récapitulatif :

<table data-full-width="true"><thead><tr><th>Fonction</th><th>Lire le contenu</th><th>Exécuter</th><th>URL distante</th></tr></thead><tbody><tr><td><strong>PHP</strong></td><td></td><td></td><td></td></tr><tr><td><code>include()</code>/<code>include_once()</code></td><td>✅</td><td>✅</td><td>✅</td></tr><tr><td><code>require()</code>/<code>require_once()</code></td><td>✅</td><td>✅</td><td>❌</td></tr><tr><td><code>file_get_contents()</code></td><td>✅</td><td>❌</td><td>✅</td></tr><tr><td><strong>NodeJS</strong></td><td></td><td></td><td></td></tr><tr><td><code>fs.readFile()</code></td><td>✅</td><td>❌</td><td>❌</td></tr><tr><td><code>res.render()</code></td><td>✅</td><td>✅</td><td>❌</td></tr><tr><td><strong>Java</strong></td><td></td><td></td><td></td></tr><tr><td><code>include</code></td><td>✅</td><td>❌</td><td>❌</td></tr><tr><td><code>import</code></td><td>✅</td><td>✅</td><td>✅</td></tr><tr><td><strong>.NET</strong></td><td></td><td></td><td></td></tr><tr><td><code>@Html.Partial()</code></td><td>✅</td><td>❌</td><td>❌</td></tr><tr><td><code>Response.WriteFile()</code></td><td>✅</td><td>❌</td><td>❌</td></tr></tbody></table>
