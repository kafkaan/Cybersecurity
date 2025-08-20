# Fuzzing des Paramètres

## <mark style="color:red;">Introduction au fuzzing de paramètres GET</mark>

Lorsque nous analysons la page `http://admin.academy.htb:PORT/admin/admin.php`, nous pouvons observer qu'un paramètre pourrait être nécessaire pour accéder à certaines fonctionnalités. L'objectif est de trouver des paramètres cachés qui pourraient permettre de lire un drapeau (flag) ou d'accéder à des zones restreintes.

#### Fuzzing des paramètres GET

Les paramètres GET sont généralement transmis directement après l'URL, précédés par un `?`, par exemple :

```
http://admin.academy.htb:PORT/admin/admin.php?param1=key
```

Pour fuzzifier les paramètres GET, nous utilisons ffuf comme suit :

{% code overflow="wrap" fullWidth="true" %}
```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```
{% endcode %}

* **Wordlist** : `/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt`.
* **URL cible** : `http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key`.
* **Filtrage** : On filtre les réponses par taille `-fs xxx` pour éliminer les réponses par défaut.

Exemple de résultat :

```
[Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

Si un paramètre valide est trouvé, nous pouvons visiter l'URL pour vérifier s'il permet d'accéder à de nouvelles informations :

```
http://admin.academy.htb:PORT/admin/admin.php?REDACTED=key
```

***

## <mark style="color:red;">Parameter Fuzzing - POST</mark>

***

The main difference between `POST` requests and `GET` requests is that `POST` requests are not passed with the URL and cannot simply be appended after a `?` symbol. `POST` requests are passed in the `data` field within the HTTP request. Check out the [Web Requests](https://academy.hackthebox.com/module/details/35) module to learn more about HTTP requests.

To fuzz the `data` field with `ffuf`, we can use the `-d` flag, as we saw previously in the output of `ffuf -h`. We also have to add `-X POST` to send `POST` requests.

Tip: In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'".

So, let us repeat what we did earlier, but place our `FUZZ` keyword after the `-d` flag:

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx

```
{% endcode %}

As we can see this time, we got a couple of hits, the same one we got when fuzzing `GET` and another parameter, which is `id`. Let's see what we get if we send a `POST` request with the `id` parameter. We can do that with `curl`, as follows:

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'

<div class='center'><p>Invalid id!</p></div>
<...SNIP...>
```
{% endcode %}

As we can see, the message now says `Invalid id!`.
