# Type Filters

There are two common methods for validating the file content: **`Content-Type`**` ``Header` or **`File Content`**. Let's see how we can identify each filter and how to bypass both of them.

***

### <mark style="color:red;">Content-Type</mark>

Let's start the exercise at the end of this section and attempt to upload a PHP script:

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_content_type_upload.jpg" alt=""><figcaption></figcaption></figure>

We see that we get a message saying `Only images are allowed`. The error message persists, and our file fails to upload even if we try some of the tricks we learned in the previous sections. If we change the file name to `shell.jpg.phtml` or `shell.php.jpg`, or even if we use `shell.jpg` with a web shell content, our upload will fail. As the file extension does not affect the error message, the web application must be testing the file content for type validation. As mentioned earlier, this can be either in the `Content-Type Header` or the `File Content`.

The following is an example of how a PHP web application tests the Content-Type header to validate the file type:

```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

The code sets the (`$type`) variable from the uploaded file's `Content-Type` header. Our browsers automatically set the Content-Type header when selecting a file through the file selector dialog, usually derived from the file extension. However, since our browsers set this, this operation is a client-side operation, and we can manipulate it to change the perceived file type and potentially bypass the type filter.

We may start by fuzzing the Content-Type header with SecLists' [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) through Burp Intruder, to see which types are allowed. However, the message tells us that only images are allowed, so we can limit our scan to image types, which reduces the wordlist to `45` types only (compared to around 700 originally). We can do so as follows:

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
mrroboteLiot@htb[/htb]$ cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```
{% endcode %}

Exercise: Try to run the above scan to find what Content-Types are allowed.

For the sake of simplicity, let's just pick an image type (e.g. `image/jpg`), then intercept our upload request and change the Content-Type header to it:

<figure><img src="../../.gitbook/assets/image (65).png" alt=""><figcaption></figcaption></figure>

This time we get `File successfully uploaded`, and if we visit our file, we see that it was successfully uploaded:

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell.jpg)

{% hint style="warning" %}
Note: A file upload HTTP request has two Content-Type headers, one for the attached file (at the bottom), and one for the full request (at the top). We usually need to modify the file's Content-Type header, but in some cases the request will only contain the main Content-Type header (e.g. if the uploaded content was sent as `POST` data), in which case we will need to modify the main Content-Type header.
{% endhint %}

***

### <mark style="color:red;">MIME-Type</mark>

The second and more common type of file content validation is testing the uploaded file's `MIME-Type`. `Multipurpose Internet Mail Extensions (MIME)` is an internet standard that determines the type of a file through its general format and bytes structure.

This is usually done by inspecting the first few bytes of the file's content, which contain the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures) or [Magic Bytes](https://opensource.apple.com/source/file/file-23/file/magic/magic.mime). For example, if a file starts with (`GIF87a` or `GIF89a`), this indicates that it is a `GIF` image, while a file starting with plaintext is usually considered a `Text` file. If we change the first bytes of any file to the GIF magic bytes, its MIME type would be changed to a GIF image, regardless of its remaining content or extension.

Tip: Many other image types have non-printable bytes for their file signatures, while a `GIF` image starts with ASCII printable bytes (as shown above), so it is the easiest to imitate. Furthermore, as the string `GIF8` is common between both GIF signatures, it is usually enough to imitate a GIF image.

Let's take a basic example to demonstrate this. The `file` command on Unix systems finds the file type through the MIME type. If we create a basic file with text in it, it would be considered as a text file, as follows:

```shell-session
mrroboteLiot@htb[/htb]$ echo "this is a text file" > text.jpg 
mrroboteLiot@htb[/htb]$ file text.jpg 
text.jpg: ASCII text
```

As we see, the file's MIME type is `ASCII text`, even though its extension is `.jpg`. However, if we write `GIF8` to the beginning of the file, it will be considered as a `GIF` image instead, even though its extension is still `.jpg`:

```shell-session
mrroboteLiot@htb[/htb]$ echo "GIF8" > text.jpg 
mrroboteLiot@htb[/htb]$file text.jpg
text.jpg: GIF image data
```

Web servers can also utilize this standard to determine file types, which is usually more accurate than testing the file extension. The following example shows how a PHP web application can test the MIME type of an uploaded file:

```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

As we can see, the MIME types are similar to the ones found in the Content-Type headers, but their source is different, as PHP uses the `mime_content_type()` function to get a file's MIME type. Let's try to repeat our last attack, but now with an exercise that tests both the Content-Type header and the MIME type:

<figure><img src="../../.gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>

Once we forward our request, we notice that we get the error message `Only images are allowed`. Now, let's try to add `GIF8` before our PHP code to try to imitate a GIF image while keeping our file extension as `.php`, so it would execute PHP code regardless:

<figure><img src="../../.gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

This time we get `File successfully uploaded`, and our file is successfully uploaded to the server:

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_bypass_mime_type.jpg" alt=""><figcaption></figcaption></figure>

We can now visit our uploaded file, and we will see that we can successfully execute system commands:

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell_gif.jpg)

{% hint style="warning" %}
**Remarque :** Nous constatons que la sortie de la commande commence par **GIF8**, car c'était la première ligne de notre script PHP, utilisée pour **imiter les magic bytes d’un fichier GIF**. Cette ligne est maintenant affichée en texte brut avant que notre code PHP ne soit exécuté.

Nous pouvons utiliser **une combinaison des deux méthodes** discutées dans cette section pour tenter de **contourner des filtres de contenu plus robustes**.

Par exemple, nous pouvons essayer :

* **Un type MIME autorisé** avec **un Content-Type interdit**
* **Un type MIME/Content-Type autorisé** avec **une extension interdite**
* **Un type MIME/Content-Type interdit** avec **une extension autorisée**

Nous pouvons également tester **d'autres combinaisons et permutations** pour essayer de **tromper le serveur web**. Selon le **niveau de sécurité du code**, ces techniques peuvent permettre de **contourner divers filtres**.
{% endhint %}
