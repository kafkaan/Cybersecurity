# Whitelist Filters

***

### <mark style="color:red;">Whitelisting Extensions</mark>

Let's start the exercise at the end of this section and attempt to upload an uncommon PHP extension, like `.phtml`, and see if we are still able to upload it as we did in the previous section:

We see that we get a message saying `Only images are allowed`, which may be more common in web apps than seeing a blocked extension type. However, error messages do not always reflect which form of validation is being utilized, so let's try to fuzz for allowed extensions as we did in the previous section, using the same wordlist that we used previously:

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_whitelist_fuzz.jpg" alt=""><figcaption></figcaption></figure>

We can see that all variations of PHP extensions are blocked (e.g. `php5`, `php7`, `phtml`). However, the wordlist we used also contained other 'malicious' extensions that were not blocked and were successfully uploaded. So, let's try to understand how we were able to upload these extensions and in which cases we may be able to utilize them to execute PHP code on the back-end server.

The following is an example of a file extension whitelist test:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

***

### <mark style="color:red;">Double Extensions</mark>

The code only tests whether the file name contains an image extension; a straightforward method of passing the regex test is through `Double Extensions`. For example, if the `.jpg` extension was allowed, we can add it in our uploaded file name and still end our filename with `.php` (e.g. `shell.jpg.php`), in which case we should be able to pass the whitelist test, while still uploading a PHP script that can execute PHP code.

Exercise: Try to fuzz the upload form with [This Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) to find what extensions are whitelisted by the upload form.

Let's intercept a normal upload request, and modify the file name to (`shell.jpg.php`), and modify its content to that of a web shell:

<figure><img src="../../.gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

Now, if we visit the uploaded file and try to send a command, we can see that it does indeed successfully execute system commands, meaning that the file we uploaded is a fully working PHP script:

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell.jpg)

However, this may not always work, as some web applications may use a strict `regex` pattern, as mentioned earlier, like the following:

```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
```

***

### <mark style="color:red;">Reverse Double Extension</mark>

In some cases, the file upload functionality itself may not be vulnerable, but the web server configuration may lead to a vulnerability. For example, an organization may use an open-source web application, which has a file upload functionality. Even if the file upload functionality uses a strict regex pattern that only matches the final extension in the file name, the organization may use the insecure configurations for the web server.

For example, the `/etc/apache2/mods-enabled/php7.4.conf` for the `Apache2` web server may include the following configuration:

```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

The above configuration is how the web server determines which files to allow PHP code execution. It specifies a whitelist with a regex pattern that matches `.phar`, `.php`, and `.phtml`. However, this regex pattern can have the same mistake we saw earlier if we forget to end it with (`$`). In such cases, any file that contains the above extensions will be allowed PHP code execution, even if it does not end with the PHP extension. For example, the file name (`shell.php.jpg`) should pass the earlier whitelist test as it ends with (`.jpg`), and it would be able to execute PHP code due to the above misconfiguration, as it contains (`.php`) in its name.

<figure><img src="../../.gitbook/assets/image (64).png" alt=""><figcaption></figcaption></figure>

Now, we can visit the uploaded file, and attempt to execute a command:

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell.jpg)

***

### <mark style="color:red;">Character Injection</mark>

Enfin, discutons d'une autre méthode pour contourner un test de validation de liste blanche grâce à l'**injection de caractères**.

Nous pouvons injecter **plusieurs caractères avant ou après l’extension finale** afin d’amener l’application web à **mal interpréter le nom du fichier** et à **exécuter le fichier téléversé comme un script PHP**.

Les caractères suivants peuvent être essayés pour l’injection :

* **%20**
* **%0a**
* **%00**
* **%0d0a**
* **/**
* \*_.\*_
* **.**
* **…**
* **:**

Chaque caractère a un **cas d’utilisation spécifique** qui peut **tromper** l’application web pour qu’elle **mal interprète l’extension du fichier**.

Par exemple :

* 📌 **`shell.php%00.jpg`** fonctionne sur les serveurs PHP en version **5.X ou antérieure**.
  * Cela force le serveur PHP à **ignorer tout après** `%00` (null byte).
  * Le fichier est stocké sous le nom **`shell.php`** tout en passant le test de liste blanche.
* 📌 **Sur un serveur Windows**, on peut **injecter un deux-points (`:`)** avant l’extension autorisée :
  * Exemple : **`shell.aspx:.jpg`**
  * Cela stocke le fichier sous le nom **`shell.aspx`** alors que la validation pense que c'est une image.

De même, **chaque autre caractère** a une utilisation potentielle qui pourrait permettre de téléverser un script PHP tout en **contournant le test de validation du type de fichier**.

```
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
```

```bash
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

With this custom wordlist, we can run a fuzzing scan with `Burp Intruder`, similar to the ones we did earlier. If either the back-end or the web server is outdated or has certain misconfigurations, some of the generated filenames may bypass the whitelist test and execute PHP code.
