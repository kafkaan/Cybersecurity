# Absent Validation

***

The most basic type of file upload vulnerability occurs when the web application `does not have any form of validation filters` on the uploaded files, allowing the upload of any file type by default.

With these types of vulnerable web apps, we may directly upload our web shell or reverse shell script to the web application, and then by just visiting the uploaded script, we can interact with our web shell or send the reverse shell.

***

### <mark style="color:red;">Arbitrary File Upload</mark>

Let's start the exercise at the end of this section, and we will see an `Employee File Manager` web application, which allows us to upload personal files to the web application:

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_file_manager.jpg" alt=""><figcaption></figcaption></figure>

The web application does not mention anything about what file types are allowed, and we can drag and drop any file we want, and its name will appear on the upload form, including `.php` files:

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_file_selected_php_file.jpg" alt=""><figcaption></figcaption></figure>

Furthermore, if we click on the form to select a file, the file selector dialog does not specify any file type, as it says `All Files` for the file type, which may also suggest that no type of restrictions or limitations are specified for the web application:

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_file_selection_dialog.jpg" alt=""><figcaption></figcaption></figure>

All of this tells us that the program appears to have no file type restrictions on the front-end, and if no restrictions were specified on the back-end, we might be able to upload arbitrary file types to the back-end server to gain complete control over it.

***

### <mark style="color:red;">Identifying Web Framework</mark>

Pour tester si une application web permet le téléversement de fichiers arbitraires et exploiter le serveur back-end, on peut téléverser un script malveillant, tel qu’un **Web Shell** ou un **Reverse Shell**.

<mark style="color:green;">**Web Shell**</mark>

* Permet d'interagir avec le serveur back-end en exécutant des commandes système et en affichant les résultats via le navigateur.
* Doit être écrit dans le même langage de programmation utilisé par le serveur web (ex. : PHP, ASP).
* Non compatible entre plateformes, car il utilise des fonctions spécifiques au système.

<mark style="color:green;">**Identification du langage utilisé par l'application web**</mark>

1. **Examiner l'extension des pages web dans l’URL** :
   * Exemple : Visiter `http://IP_SERVEUR:PORT/index.php` pour vérifier si le serveur utilise PHP.
2. **Utiliser des outils comme Burp Intruder** :
   * Permet de tester automatiquement des extensions courantes (php, asp, aspx, etc.) avec une liste de mots.
3. **Utiliser des extensions comme Wappalyzer** :
   * Identifie le langage, la version du serveur, le système d’exploitation, et d'autres technologies.
4. **Scanners web** :
   * Outils comme Burp/ZAP pour détecter le framework ou le langage utilisé.

Une fois le langage identifié, on peut téléverser un script malveillant écrit dans ce langage pour exploiter l'application et potentiellement prendre le contrôle à distance du serveur back-end.

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_wappalyzer.jpg" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">Vulnerability Identification</mark>

Now that we have identified the web framework running the web application and its programming language, we can test whether we can upload a file with the same extension. As an initial test to identify whether we can upload arbitrary `PHP` files, let's create a basic `Hello World` script to test whether we can execute `PHP` code with our uploaded file.

To do so, we will write `<?php echo "Hello HTB";?>` to `test.php`, and try uploading it to the web application:

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_upload_php.jpg" alt=""><figcaption></figcaption></figure>

```
http://SERVER_IP:PORT/uploads/test.php
```

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_hello_htb.jpg)
