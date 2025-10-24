# PHP Web Shells

***

Hypertext Preprocessor or [PHP](https://www.php.net) is an open-source general-purpose scripting language typically used as part of a web stack that powers a website. At the time of this writing (October 2021), PHP is the most popular `server-side programming language`. According to a [recent survey](https://w3techs.com/technologies/details/pl-php) conducted by W3Techs, "PHP is used by `78.6%` of all websites whose server-side programming language we know".

<mark style="color:green;">**PHP Login Page**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/rconfig.png)

***

### <mark style="color:red;">Hands-on With a PHP-Based Web Shell.</mark>

Go ahead and log in to rConfig with the default credentials (admin:admin), then navigate to `Devices` > `Vendors` and click `Add Vendor`.

<mark style="color:green;">**Vendors Tab**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/vendors_tab.png)

* On utilisera la **PHP Web Shell** de WhiteWinterWolf (télécharger ou coller le code dans un fichier `.php`).
* L’extension **est importante** : rConfig vérifie le type de fichier et n’accepte que les images (`.png`, `.jpg`, `.gif`, …).
* Pour comprendre pourquoi l’upload échoue, on fait passer les requêtes HTTP par un **proxy d’interception** (ex. Burp Suite) afin d’inspecter la requête d’upload.
* L’intérêt d’un proxy : **voir** exactement ce que le navigateur envoie (en‑têtes, nom de fichier, type MIME, corps multipart, etc.) et **expérimenter** comment le serveur valide le fichier — uniquement en lab.
* Dans un contexte d’apprentissage (HTB/lab autorisé), on peut alors tester des modifications **pour mieux comprendre** les contrôles côté serveur et les protections à renforcer.

<mark style="color:green;">**Proxy Settings**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/proxy_settings.png)

Our goal is to change the `content-type` to bypass the file type restriction in uploading files to be "presented" as the vendor logo so we can navigate to that file and have our web shell.

***

### <mark style="color:red;">Bypassing the File Type Restriction</mark>

* Avec Burp Suite ouvert et le navigateur configuré pour passer par le **proxy**, toute requête HTTP passe par Burp.
* L’upload du fichier `.php` peut sembler bloqué, car Burp intercepte les requêtes — il faut **forwarder** les requêtes pour qu’elles continuent vers le serveur.
* En forwardant, on peut observer le **POST contenant le fichier** et analyser exactement ce qui est envoyé (nom du fichier, type MIME, corps multipart).
* Cela permet de **comprendre le mécanisme de validation côté serveur** et comment rConfig filtre certains types de fichiers.
* Concept clé : l’outil d’interception permet de **tester et observer les requêtes HTTP** sans exécuter d’action malveillante sur un système réel.

<mark style="color:green;">**Post Request**</mark>

![Burp](https://academy.hackthebox.com/storage/modules/115/burp.png)

As mentioned in an earlier section, you will notice that some payloads have comments from the author that explain usage, provide kudos and links to personal blogs. This can give us away, so it's not always best to leave the comments in place. We will change Content-type from `application/x-php` to `image/gif`. This will essentially "trick" the server and allow us to upload the .php file, bypassing the file type restriction. Once we do this, we can select `Forward` twice, and the file will be submitted. We can turn the Burp interceptor off now and go back to the browser to see the results.

<mark style="color:green;">**Vendor Added**</mark>

![Burp](https://academy.hackthebox.com/storage/modules/115/added_vendor.png)

The message: 'Added new vendor NetVen to Database\` lets us know our file upload was successful. We can also see the NetVen vendor entry with the logo showcasing a ripped piece of paper. This means rConfig did not recognize the file type as an image, so it defaulted to that image. We can now attempt to use our web shell. Using the browser, navigate to this directory on the rConfig server:

`/images/vendor/connect.php`

This executes the payload and provides us with a non-interactive shell session entirely in the browser, allowing us to execute commands on the underlying OS.

<mark style="color:green;">**Webshell Success**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/web_shell_now.png)

***

