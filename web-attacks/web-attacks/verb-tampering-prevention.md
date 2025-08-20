# Verb Tampering Prevention

<mark style="color:blue;">**Configuration Insecure**</mark>

Les vulnérabilités de manipulation des verbes HTTP peuvent survenir dans la plupart des serveurs web modernes, comme <mark style="color:orange;">**Apache, Tomcat et ASP.NE**</mark><mark style="color:orange;">T</mark>. La vulnérabilité se produit généralement lorsque l'autorisation d'une page est limitée à un ensemble particulier de verbes HTTP, laissant les autres méthodes non protégées.

Voici un exemple de configuration vulnérable pour un serveur Apache, située dans le fichier de configuration du site (par exemple, `000-default.conf`) ou dans un fichier `.htaccess` :

```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

Dans cette configuration, l'authentification est définie pour le répertoire `/admin`. Cependant, comme le mot-clé `<Limit GET>` est utilisé, la configuration `Require valid-user` ne s'applique qu'aux requêtes GET, laissant la page accessible via les requêtes POST. Même si GET et POST étaient spécifiés, d'autres méthodes, comme HEAD ou OPTIONS, seraient encore accessibles.

Un exemple similaire pour un serveur Tomcat :

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

Dans cet exemple, l'autorisation est limitée à la méthode GET, ce qui laisse la page accessible par d'autres méthodes HTTP.

Pour ASP.NET :

```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
        <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```

L'autorisation est de nouveau limitée à la méthode GET, permettant l'accès via d'autres méthodes HTTP.

Ces exemples montrent qu'il n'est pas sûr de limiter la configuration d'autorisation à un seul verbe HTTP. Il est préférable de ne pas restreindre l'autorisation à un verbe HTTP spécifique et de toujours permettre/interdire tous les verbes et méthodes HTTP.

***

<mark style="color:blue;">**Codage Insecure**</mark>

Bien que l'identification et la correction des configurations vulnérables du serveur web soient relativement simples, le même processus pour le code vulnérable est beaucoup plus complexe. Cela s'explique par le fait qu'il faut identifier les incohérences dans l'utilisation des paramètres HTTP à travers les fonctions, ce qui peut entraîner des fonctionnalités non protégées et des filtres contournés.

Prenons le code PHP suivant :

```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```

Dans ce code, la fonction `preg_match` vérifie correctement la présence de caractères spéciaux non désirés dans les paramètres POST. Cependant, l'erreur fatale ici est l'incohérence dans l'utilisation des méthodes HTTP.

**La fonction `preg_match` vérifie uniquement les paramètres POST (`$_POST['filename']`), tandis que la commande `system` utilise `$_REQUEST['filename']`, qui couvre à la fois les paramètres GET et POST**. Ainsi, en envoyant des données malveillantes via une requête GET, la fonction `preg_match` ne bloque pas la requête, car les paramètres POST étaient vides, mais une fois dans la fonction système, les paramètres GET sont utilisés, permettant ainsi l'injection de commandes.

Cet exemple montre comment de petites incohérences dans l'utilisation des méthodes HTTP peuvent conduire à des vulnérabilités graves. Dans une application de production, ces vulnérabilités ne seront probablement pas aussi évidentes et pourraient être dispersées à travers l'application.
