# Catching Files over HTTP/S

***

### <mark style="color:red;">HTTP/S</mark>

### <mark style="color:blue;">Nginx - Enabling PUT</mark>

<mark style="color:green;">**Alternative à Apache**</mark>

* Nginx est une bonne alternative à Apache pour le transfert de fichiers
* Configuration moins compliquée qu'Apache
* Système de modules plus sécurisé (évite les failles de sécurité courantes d'Apache)

<mark style="color:green;">**Sécurité des uploads HTTP**</mark>

* Risque critique : empêcher l'upload et l'exécution de web shells par les utilisateurs
* Nécessite une vigilance absolue (100% de certitude)

<mark style="color:green;">**Comparaison Apache vs Nginx**</mark>

* **Apache** : risque élevé car le module PHP exécute facilement tout fichier se terminant par `.php`
* **Nginx** : configuration PHP beaucoup plus complexe, donc plus sécurisée par défaut
* Nginx réduit le risque d'erreurs de configuration dangereuses

**Avantage sécurité**

* La complexité de configuration PHP sous Nginx devient un atout de sécurité

<mark style="color:orange;">**Create a Directory to Handle Uploaded Files**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```
{% endcode %}

<mark style="color:orange;">**Change the Owner to www-data**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```
{% endcode %}

<mark style="color:orange;">**Create Nginx Configuration File**</mark>

Create the Nginx configuration file by creating the file `/etc/nginx/sites-available/upload.conf` with the contents:

```nginx
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

<mark style="color:orange;">**Symlink our Site to the sites-enabled Directory**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```
{% endcode %}

<mark style="color:orange;">**Start Nginx**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo systemctl restart nginx.service
```
{% endcode %}

If we get any error messages, check `/var/log/nginx/error.log`. If using Pwnbox, we will see port 80 is already in use.

<mark style="color:orange;">**Verifying Errors**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ tail -2 /var/log/nginx/error.log
```
{% endcode %}

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ ss -lnpt | grep 80
```
{% endcode %}

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ ps -ef | grep 2811
```
{% endcode %}

We see there is already a module listening on port 80. To get around this, we can remove the default Nginx configuration, which binds on port 80.

<mark style="color:orange;">**Remove NginxDefault Configuration**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo rm /etc/nginx/sites-enabled/default
```

Now we can test uploading by using `cURL` to send a `PUT` request. In the below example, we will upload the `/etc/passwd` file to the server and call it users.txt

<mark style="color:orange;">**Upload File Using cURL**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```
{% endcode %}

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt 

user65:x:1000:1000:,,,:/home/user65:/bin/bash
```
{% endcode %}

Once we have this working, a good test is to ensure the directory listing is not enabled by navigating to `http://localhost/SecretUploadDirectory`. By default, with `Apache`, if we hit a directory without an index file (index.html), it will list all the files. This is bad for our use case of exfilling files because most files are sensitive by nature, and we want to do our best to hide them. Thanks to `Nginx` being minimal, features like that are not enabled by default.

***
