# Introduction aux Injections SQL

## <mark style="color:red;">**Utilisation de SQL dans les Applications Web**</mark>

Les applications web utilisent des bases de données (comme MySQL dans ce cas) pour stocker et récupérer des données. Une fois qu'un système de gestion de base de données (DBMS) est installé sur le serveur, les applications web peuvent l'utiliser pour interagir avec la base de données.

Dans une application PHP, par exemple, nous pouvons nous connecter à la base de données et commencer à utiliser MySQL directement dans PHP, comme suit :

```php
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);
```

Ensuite, le résultat de la requête est stocké dans la variable `$result`, et nous pouvons l'afficher sur la page web ou l'utiliser de toute autre manière.

```php
while($row = $result->fetch_assoc() ){
    echo $row["name"]."<br>";
}
```

Les applications web utilisent également des entrées utilisateur pour récupérer des données. Par exemple, si un utilisateur effectue une recherche, la saisie de l'utilisateur est envoyée à l'application web, qui l'utilise pour rechercher dans la base de données :

```php
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

Cependant, si l'entrée de l'utilisateur n'est pas correctement sécurisée, cela peut entraîner des vulnérabilités d'injection SQL.

***

## <mark style="color:red;">**Qu'est-ce qu'une Injection SQL ?**</mark>

{% hint style="warning" %}
Une **injection SQL** se produit lorsque l'entrée utilisateur est insérée directement dans la chaîne de requête SQL sans être correctement filtrée ou assainie. Cela permet à un attaquant d'ajouter du code malveillant dans la requête SQL.
{% endhint %}

Dans l'exemple précédent, si l'entrée de l'utilisateur n'est pas assainie, un attaquant pourrait ajouter du code SQL malveillant. Par exemple, au lieu d'une recherche normale, un utilisateur pourrait entrer un code comme `1'; DROP TABLE users;`. Cela pourrait causer des effets indésirables, comme la suppression de la table "users" :

```sql
select * from logins where username like '%1'; DROP TABLE users;'
```

Dans ce cas, la requête finale exécutée pourrait être dangereuse pour la base de données.

<mark style="color:green;">**Erreurs de Syntaxe**</mark>

Lorsqu'une injection SQL est effectuée, cela peut entraîner une erreur de syntaxe. Par exemple, si un utilisateur entre une chaîne comme `'1'; DROP TABLE users;'`, cela pourrait provoquer une erreur SQL en raison de la présence de caractères non échappés.

{% hint style="danger" %}
Cependant, pour réussir une injection SQL, il est important de s'assurer que la requête SQL modifiée est valide. Si elle n'est pas valide, l'injection échouera. Parfois, des commentaires peuvent être utilisés pour contourner les erreurs de syntaxe et injecter du code valide.
{% endhint %}

***

## <mark style="color:red;">**Types d'Injections SQL**</mark>

Les injections SQL peuvent être classées en fonction de la manière dont le résultat est récupéré :

1. <mark style="color:green;">**Injections SQL en bande (In-band SQL Injection)**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark> Les résultats de la requête sont directement affichés sur le front-end. Elles se divisent en deux types :
   * **Union-Based SQL Injection** : L'attaquant spécifie l'endroit où les résultats doivent être affichés, généralement dans une colonne précise.
   * **Error-Based SQL Injection** : L'attaquant utilise les erreurs SQL pour récupérer des informations sur la base de données en provoquant des erreurs sur le serveur.
2. <mark style="color:green;">**Injections SQL aveugles (Blind SQL Injection)**</mark> : L'attaquant ne voit pas directement le résultat de la requête, mais utilise des déclarations conditionnelles pour en déduire des informations. Elle se divise en deux types :
   * **Boolean-Based Blind SQL Injection** : L'attaquant utilise des conditions pour voir si la page retourne un résultat basé sur une requête spécifique.
   * **Time-Based Blind SQL Injection** : L'attaquant utilise des délais (par exemple, `SLEEP()`) pour déterminer si une condition est vraie.
3. <mark style="color:green;">**Injections SQL hors bande (Out-of-Band SQL Injection)**</mark> : L'attaquant redirige les résultats de l'injection vers un emplacement distant, comme un enregistrement DNS, et tente de récupérer ces informations depuis cet endroit.

***
