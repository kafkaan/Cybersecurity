# Intro to HTTP Verb Tampering

## <mark style="color:blue;">**HTTP Verb Tampering**</mark>

{% hint style="warning" %}
Le protocole **HTTP** utilise différentes méthodes (GET, POST, PUT, DELETE, etc.).\
Si un serveur n’autorise que **GET** et **POST**, les autres renvoient une erreur (pas grave, mais informatif).\
Par contre, si d’autres méthodes sont mal gérées, cela peut permettre d’**accéder à des fonctions non prévues** ou de **contourner la sécurité**.
{% endhint %}

***

### <mark style="color:blue;">**HTTP Verb Tampering**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th width="290.29998779296875"></th><th></th></tr></thead><tbody><tr><td><strong>Verbe</strong></td><td><strong>Description</strong></td></tr><tr><td><strong>HEAD</strong></td><td>Identique à GET, mais ne renvoie que les en-têtes (sans contenu)</td></tr><tr><td><strong>PUT</strong></td><td>Écrit les données envoyées à un emplacement précis</td></tr><tr><td><strong>DELETE</strong></td><td>Supprime la ressource ciblée</td></tr><tr><td><strong>OPTIONS</strong></td><td>Affiche les méthodes HTTP acceptées par le serveur</td></tr><tr><td><strong>PATCH</strong></td><td>Applique des modifications partielles à une ressource</td></tr></tbody></table>

* **PUT** peut être utilisé pour **téléverser des fichiers** sur le serveur
* **DELETE** peut permettre **la suppression de fichiers**

***

### <mark style="color:blue;">**Insecure Configurations**</mark>

Une mauvaise configuration du serveur peut laisser certaines <mark style="color:orange;">**méthodes HTTP accessibles sans authentification**</mark><mark style="color:orange;">.</mark>

```xml
<Limit GET POST>
    Require valid-user
</Limit>
```

⚠️ **Problème** : ici, seule l’authentification pour GET et POST est requise. Un attaquant peut donc utiliser une autre méthode HTTP, comme **HEAD**, pour **contourner l'authentification** et accéder à la page sans se connecter.

***

### <mark style="color:blue;">**Insecure Coding**</mark>

```php
$pattern = "/^[A-Za-z\s]+$/";

if (preg_match($pattern, $_GET["code"])) {
    $query = "SELECT * FROM ports WHERE port_code LIKE '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```

🔍 **Problème** :

* **Le filtre ne s’applique qu’aux requêtes GET**
* Mais dans la requête SQL, la variable `$_REQUEST["code"]` est utilisée, ce qui inclut à la fois **GET et POST**

***
