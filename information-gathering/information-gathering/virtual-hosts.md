---
cover: ../../.gitbook/assets/virtyal.png
coverY: 0
---

# Virtual Hosts

#### <mark style="color:green;">1.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Rôle du Serveur Web**</mark>

Lorsque le DNS (Domain Name System) résout un nom de domaine en une adresse IP, cette adresse IP pointe vers un serveur web. Le serveur web est responsable de recevoir les requêtes HTTP ou HTTPS des clients (comme les navigateurs web) et de répondre avec le contenu approprié.

#### <mark style="color:green;">2.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Configuration du Serveur Web**</mark>

Une fois que le trafic est dirigé vers le serveur web par le DNS, la manière dont les requêtes sont traitées dépend de la configuration du serveur web. Les serveurs web comme **Apache**, **Nginx**, et **IIS** (Internet Information Services) sont **conçus pour gérer des requêtes pour plusieurs sites web ou applications à partir d'un seul serveur physique**.

#### <mark style="color:green;">3.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Hébergement Virtuel (Virtual Hosting)**</mark>

L'hébergement virtuel (ou virtual hosting) est une technique utilisée par les serveurs web pour héberger plusieurs sites web sur une seule machine. Voici les concepts associés :

* **Hébergement Virtuel Basé sur le Nom (Name-based Virtual Hosting)** : Le serveur web utilise le nom de domaine dans la requête HTTP pour déterminer quel site web servir. Par exemple, si une requête est faite pour `www.example.com`, le serveur web regarde dans sa configuration pour savoir comment traiter cette requête en fonction du nom de domaine.
* **Hébergement Virtuel Basé sur l'IP (IP-based Virtual Hosting)** : Dans ce cas, chaque site web a une adresse IP distincte. Le serveur web utilise l'adresse IP de la requête pour déterminer quel site web servir. Cette méthode est moins courante aujourd'hui, surtout avec la pénurie d'adresses IPv4.

#### <mark style="color:green;">4.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Exemple d'Apache et Nginx**</mark>

*   <mark style="color:orange;">**Apache**</mark> : Apache utilise des fichiers de configuration appelés "Virtual Hosts" pour gérer l'hébergement virtuel. Par exemple, dans un fichier de configuration, vous pouvez définir un bloc `<VirtualHost>` pour chaque site web que vous souhaitez héberger.

    Exemple :

    ```apacheconf
    <VirtualHost *:80>
        ServerName www.example.com
        DocumentRoot /var/www/example
    </VirtualHost>

    <VirtualHost *:80>
        ServerName www.anotherexample.com
        DocumentRoot /var/www/anotherexample
    </VirtualHost>
    ```

    Dans cet exemple, Apache sert le contenu de `/var/www/example` pour `www.example.com` et le contenu de `/var/www/anotherexample` pour `www.anotherexample.com`.
*   <mark style="color:orange;">**Nginx**</mark> : Nginx utilise également des blocs de configuration pour gérer l'hébergement virtuel, mais avec une syntaxe différente. Les configurations sont définies dans des fichiers de configuration appelés "server blocks".

    Exemple :

    ```nginx
    server {
        listen 80;
        server_name www.example.com;
        root /var/www/example;
    }

    server {
        listen 80;
        server_name www.anotherexample.com;
        root /var/www/anotherexample;
    }
    ```

    Ici, Nginx sert le contenu de `/var/www/example` pour `www.example.com` et le contenu de `/var/www/anotherexample` pour `www.anotherexample.com`.

***

## <mark style="color:red;">**1. Introduction aux Virtual Hosts**</mark>

Une fois que le DNS a dirigé le trafic vers le bon serveur, la configuration du serveur web est cruciale pour déterminer comment les requêtes entrantes sont traitées. Les serveurs web comme **Apache**, **Nginx**, ou **IIS** utilisent l'hébergement virtuel pour gérer plusieurs sites web ou applications sur un seul serveur.

***

## <mark style="color:red;">**2. Fonctionnement des Virtual Hosts**</mark>

* **Virtual Hosting (Hébergement Virtuel)** : Permet à un serveur web de différencier plusieurs sites web ou applications qui partagent la même adresse IP. Cette différenciation se fait en utilisant l'en-tête `Host` de la requête HTTP envoyée par le navigateur.

***

## <mark style="color:red;">**3. Différence entre VHosts et Subdomains**</mark>

* **Subdomains (Sous-domaines)** : Extensions d'un domaine principal (par exemple, `blog.example.com` est un sous-domaine de `example.com`). Ils ont généralement leurs propres enregistrements DNS, pointant vers la même adresse IP que le domaine principal ou une adresse différente.
* **Virtual Hosts (VHosts)** : Configurations au sein du serveur web permettant d'héberger plusieurs sites web ou applications sur un seul serveur. Ils peuvent être associés à des domaines de premier niveau ou à des sous-domaines. Chaque VHost a sa propre configuration, permettant un contrôle précis sur le traitement des requêtes.

***

## <mark style="color:red;">**4. Accès aux Virtual Hosts sans Enregistrement DNS**</mark>

Si un VHost n'a pas d'enregistrement DNS, vous pouvez encore y accéder en modifiant le fichier `hosts` de votre machine locale. Le fichier `hosts` permet de mapper manuellement un nom de domaine à une adresse IP, contournant ainsi la résolution DNS

***

## <mark style="color:red;">**5. Configuration des Virtual Hosts**</mark>

Les VHosts peuvent être configurés pour utiliser différents domaines, pas seulement des sous-domaines. Voici des exemples de configuration pour **Apache** :

**Configuration Apache** :

```apacheconf
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```

Dans cet exemple, `example1.com`, `example2.org`, et `another-example.net` sont des domaines distincts hébergés sur le même serveur. Le serveur web utilise l'en-tête `Host` pour servir le contenu approprié en fonction du nom de domaine demandé.

***

## <mark style="color:red;">**6. Processus de Détermination du Virtual Host**</mark>

1. **Demande du Navigateur** : Le navigateur envoie une requête HTTP au serveur web avec le domaine (e.g., `www.inlanefreight.com`).
2. **En-tête Host** : Le domaine est inclus dans l'en-tête `Host` de la requête HTTP.
3. **Détermination du VHost** : Le serveur web examine l'en-tête `Host`, consulte sa configuration de VHosts, et trouve une entrée correspondante pour le domaine demandé.
4. **Serve le Contenu** : Le serveur web récupère les fichiers et ressources associés à ce VHost depuis le répertoire racine et les renvoie au navigateur.

***

## <mark style="color:red;">**7. Types d'Hébergement Virtuel**</mark>

* **Hébergement Virtuel Basé sur le Nom (Name-Based Virtual Hosting)** : Utilise uniquement l'en-tête `Host` pour distinguer les sites. Flexibilité et coût réduit, mais peut avoir des limitations avec SSL/TLS.
* **Hébergement Virtuel Basé sur l'IP (IP-Based Virtual Hosting)** : Assigne une adresse IP unique à chaque site. Pas besoin de l'en-tête `Host`, mais nécessite plusieurs IP, ce qui peut être coûteux.
* **Hébergement Virtuel Basé sur le Port (Port-Based Virtual Hosting)** : Utilise différents ports sur la même IP pour différents sites. Moins courant, nécessite que les utilisateurs spécifient le port dans l'URL.

***

## <mark style="color:red;">**8. Outils de Découverte des Virtual Hosts**</mark>

<table data-full-width="true"><thead><tr><th>Tool</th><th>Description</th><th>Features</th></tr></thead><tbody><tr><td><a href="https://github.com/OJ/gobuster">gobuster</a></td><td>A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery.</td><td>Fast, supports multiple HTTP methods, can use custom wordlists.</td></tr><tr><td><a href="https://github.com/epi052/feroxbuster">Feroxbuster</a></td><td>Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility.</td><td>Supports recursion, wildcard discovery, and various filters.</td></tr><tr><td><a href="https://github.com/ffuf/ffuf">ffuf</a></td><td>Another fast web fuzzer that can be used for virtual host discovery by fuzzing the <code>Host</code> header.</td><td>Customizable wordlist input and filtering options.</td></tr></tbody></table>

### <mark style="color:blue;">**Gobuster**</mark>&#x20;

* Utilisé pour la découverte de VHosts et la force brute des répertoires/fichiers.
*   Exemple de commande :

    ```bash
    gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
    ```
* **Paramètres** :
  * `-u` : URL cible.
  * `-w` : Fichier de wordlist.
  * `--append-domain` : Ajoute le domaine de base à chaque mot de la wordlist.
