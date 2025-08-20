# Web Proxies

{% hint style="warning" %}
Les **proxies web** sont des outils spécialisés qui s'intercalent entre un navigateur/application mobile et un serveur pour capturer et observer toutes les requêtes web échangées entre ces deux points. Ils agissent comme des outils de type **"man-in-the-middle" (MITM)**.

Contrairement aux outils d'analyse réseau comme **Wireshark** qui surveillent tout le trafic réseau local, les **proxies web** travaillent principalement avec les ports web comme :

* **HTTP (port 80)**
* **HTTPS (port 443)**

Les proxies web sont essentiels pour tout testeur en cybersécurité (pentester) spécialisé dans les applications web. Ils simplifient énormément la capture et la relecture des requêtes web, ce qui était plus compliqué avec les outils en ligne de commande (CLI).

Une fois configuré, un proxy web permet de :

* Voir toutes les requêtes **HTTP** envoyées par une application.
* Observer toutes les réponses renvoyées par le serveur.
* **Intercepter et modifier** des requêtes pour tester la réaction du serveur.
{% endhint %}

***

## <mark style="color:red;">**Utilisations des Proxies Web**</mark>

Même si la principale utilisation des proxies web est de capturer et rejouer des requêtes HTTP, ils offrent aussi d'autres fonctionnalités :

* **Scan des vulnérabilités des applications web**
* **Fuzzing web** (test de réponse à des entrées aléatoires)
* **Exploration automatisée de sites (crawling)**
* **Cartographie des applications web**
* **Analyse des requêtes web**
* **Tests de configuration web**
* **Revue de code**

Dans ce module, nous ne parlerons pas des attaques web spécifiques, mais nous apprendrons à utiliser ces outils et leurs différentes fonctionnalités. Nous évoquerons les deux outils de proxy web les plus utilisés :

* **Burp Suite**
* **ZAP (Zed Attack Proxy)**

***
