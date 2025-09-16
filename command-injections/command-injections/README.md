# Command Injections

* 🔴 **Gravité** : L’injection de commandes est l’une des vulnérabilités les plus critiques.
* ⚙️ **Principe** : Elle consiste à exécuter directement des commandes système sur le serveur.
* 🌐 **Surface d’attaque** : Elle survient quand une application web utilise des entrées utilisateur pour appeler des commandes système.
* 💣 **Exploitation** : Un attaquant peut injecter une charge malveillante afin de détourner la commande prévue.
* 📉 **Impact** : Cela peut compromettre totalement le serveur et, par extension, tout le réseau auquel il appartient.

***

## <mark style="color:red;">Qu'est-ce qu'une Injection ?</mark>

Les vulnérabilités d'injection figurent au **troisième rang** des risques identifiés dans le **Top 10 OWASP** des applications web

Il existe plusieurs types d'injections dans les applications web, selon la nature de la requête exécutée. Voici quelques-unes des plus courantes :

<table data-full-width="true"><thead><tr><th>Type d'injection</th><th>Description</th></tr></thead><tbody><tr><td><strong>Injection de commandes système</strong></td><td>Se produit lorsque les entrées utilisateur sont utilisées directement dans une commande système.</td></tr><tr><td><strong>Injection de code</strong></td><td>Se produit lorsque les entrées utilisateur sont insérées dans une fonction qui exécute du code.</td></tr><tr><td><strong>Injection SQL</strong></td><td>Se produit lorsque les entrées utilisateur sont utilisées dans une requête SQL.</td></tr><tr><td><strong>Injection HTML/XSS</strong></td><td>Se produit lorsque les entrées utilisateur sont affichées telles quelles sur une page web.</td></tr></tbody></table>

D'autres types d'injections incluent **LDAP Injection**, **NoSQL Injection**, **Injection d'en-têtes HTTP**, **XPath Injection**, **Injection IMAP**, **Injection ORM**, etc.

***

## <mark style="color:red;">Injection de Commandes Système</mark>

* 🔹 **Définition** : Entrée utilisateur influençant l’exécution de commandes système.
* 🔹 **Fonctions concernées** : Tous les langages web offrent des moyens d’exécuter des commandes serveur.
* 🔹 **Usage légitime** : Installer des plugins, lancer des applications ou automatiser des tâches.
* 🔹 **Risque** : Si mal contrôlé, l’entrée peut être détournée pour exécuter du code malveillant.

<mark style="color:green;">**Exemple en PHP**</mark>

En PHP, des fonctions comme **exec**, **system**, **shell\_exec**, **passthru**, ou **popen** permettent d'exécuter des commandes système.

```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

***

<mark style="color:green;">**Exemple en NodeJS**</mark>

Cette vulnérabilité n'est pas spécifique à PHP. En NodeJS, des fonctions comme **child\_process.exec** ou **child\_process.spawn** peuvent être utilisées de manière similaire.

```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

***
