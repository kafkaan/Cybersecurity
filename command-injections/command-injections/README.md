# Command Injections

Une vulnérabilité d'injection de commandes est l'une des plus critiques. **Elle permet d'exécuter des commandes système directement sur le serveur hébergeant l'application, ce qui peut compromettre l'ensemble du résea**u. Si une application web utilise des entrées contrôlées par l'utilisateur pour exécuter des commandes système sur le serveur afin d'obtenir et de retourner des résultats spécifiques, il est possible d'injecter une charge malveillante pour détourner la commande prévue et exécuter nos propres commandes.

***

## <mark style="color:red;">Qu'est-ce qu'une Injection ?</mark>

Les vulnérabilités d'injection figurent au **troisième rang** des risques identifiés dans le **Top 10 OWASP** des applications web

Il existe plusieurs types d'injections dans les applications web, selon la nature de la requête exécutée. Voici quelques-unes des plus courantes :

<table data-full-width="true"><thead><tr><th>Type d'injection</th><th>Description</th></tr></thead><tbody><tr><td><strong>Injection de commandes système</strong></td><td>Se produit lorsque les entrées utilisateur sont utilisées directement dans une commande système.</td></tr><tr><td><strong>Injection de code</strong></td><td>Se produit lorsque les entrées utilisateur sont insérées dans une fonction qui exécute du code.</td></tr><tr><td><strong>Injection SQL</strong></td><td>Se produit lorsque les entrées utilisateur sont utilisées dans une requête SQL.</td></tr><tr><td><strong>Injection HTML/XSS</strong></td><td>Se produit lorsque les entrées utilisateur sont affichées telles quelles sur une page web.</td></tr></tbody></table>

D'autres types d'injections incluent **LDAP Injection**, **NoSQL Injection**, **Injection d'en-têtes HTTP**, **XPath Injection**, **Injection IMAP**, **Injection ORM**, etc.

***

## <mark style="color:red;">Injection de Commandes Système</mark>

Dans une injection de commandes système, l'entrée utilisateur contrôlée doit directement ou indirectement affecter une commande système exécutée par l'application. Tous les langages de programmation web offrent des fonctions permettant d'exécuter des commandes système sur le serveur. Ces fonctions sont utilisées pour diverses tâches, comme l'installation de plugins ou l'exécution d'applications spécifiques.

<mark style="color:green;">**Exemple en PHP**</mark>

En PHP, des fonctions comme **exec**, **system**, **shell\_exec**, **passthru**, ou **popen** permettent d'exécuter des commandes système. Voici un exemple de code vulnérable en PHP :

```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

Ce code permet à l'utilisateur de créer un fichier PDF dans le répertoire `/tmp`, avec un nom fourni par la requête GET. Cependant, comme l'entrée utilisateur (le paramètre `filename`) est utilisée directement dans la commande **touch** sans validation ou nettoyage, l'application devient vulnérable à une injection de commandes.

***

<mark style="color:green;">**Exemple en NodeJS**</mark>

Cette vulnérabilité n'est pas spécifique à PHP. En NodeJS, des fonctions comme **child\_process.exec** ou **child\_process.spawn** peuvent être utilisées de manière similaire. Voici un exemple en NodeJS :

```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

Dans cet exemple, le paramètre `filename` de la requête GET est directement intégré dans une commande sans être validé. Ce code est également vulnérable à une injection de commandes.

***
