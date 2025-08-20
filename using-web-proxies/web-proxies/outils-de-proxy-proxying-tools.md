# Outils de Proxy (Proxying Tools)

***

## <mark style="color:red;">**Proxychains**</mark>

Un outil très utile sous Linux est **proxychains**. Il redirige tout le trafic généré par n'importe quel outil en ligne de commande vers un proxy spécifié. Proxychains ajoute un proxy à tout outil CLI, ce qui en fait la méthode la plus simple et rapide pour rediriger le trafic web des outils en ligne de commande à travers nos proxys web.

**Configuration de&#x20;**<mark style="color:green;">**proxychains**</mark>**&#x20;:**

1.  Éditez le fichier de configuration `/etc/proxychains.conf` :

    ```bash
    sudo nano /etc/proxychains.conf
    ```
2.  Commentez la dernière ligne :

    ```bash
    # socks4 127.0.0.1 9050
    ```
3.  Ajoutez cette ligne à la fin :

    ```bash
    http 127.0.0.1 8080
    ```
4.  Activez le **mode silencieux** (quiet mode) pour réduire les logs inutiles :

    ```bash
    uncomment quiet_mode
    ```

Une fois cette configuration effectuée, il suffit de préfixer n'importe quelle commande par `proxychains` pour rediriger son trafic à travers le proxy.

**Exemple :**

```bash
baproxychains curl http://SERVEUR_IP:PORT
```

**Résultat :**

```html
ProxyChains-3.1 (http://proxychains.sf.net)
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Ping IP</title>
    <link rel="stylesheet" href="./style.css">
</head>
...SNIP...
</html>
```

Le fait que `ProxyChains-3.1` s'affiche indique que la commande a été routée par proxychains. Si nous retournons dans notre outil proxy (Burp par exemple), nous verrons que la requête est bien passée par le proxy.

***

## <mark style="color:red;">**Nmap**</mark>

Voyons maintenant comment proxyfier **nmap**. Pour découvrir comment utiliser les options de proxy d'un outil, nous pouvons consulter son manuel avec `man nmap` ou sa page d'aide avec `nmap -h`.

**Exemple :**

```bash
nmap -h | grep -i prox
```

**Résultat :**

{% code fullWidth="true" %}
```bash
--proxies <url1,[url2],...> : Relayer les connexions via des proxys HTTP/SOCKS4
```
{% endcode %}

Nous pouvons donc utiliser l'option `--proxies`. Il est également recommandé d'ajouter l'option `-Pn` pour ignorer la détection d'hôte (comme mentionné dans le manuel). Enfin, nous utiliserons `-sC` pour effectuer un scan avec des scripts nmap.

**Exemple de commande complète :**

```bash
nmap --proxies http://127.0.0.1:8080 SERVEUR_IP -pPORT -Pn -sC
```

**Résultat :**

```bash
Starting Nmap 7.91 ( https://nmap.org )
Nmap scan report for SERVEUR_IP
Host is up (0.11s latency).

PORT      STATE SERVICE
PORT/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
```

Si nous vérifions notre outil proxy, nous verrons les requêtes de nmap dans l'historique du proxy.

**Remarque :**\
Le proxy intégré de nmap est encore en phase expérimentale (comme mentionné dans le manuel). Par conséquent, certaines fonctions ou trafics peuvent ne pas être correctement redirigés. Dans ces cas, nous pouvons simplement utiliser **proxychains**, comme précédemment.

***

## <mark style="color:red;">**Metasploit**</mark>

Enfin, voyons comment proxyfier les requêtes web générées par les modules de **Metasploit** pour mieux les analyser et les déboguer.

**Configuration :**

1.  Lancez Metasploit :

    ```bash
    msfconsole
    ```
2.  Configurez un proxy pour un module spécifique. Par exemple, le scanner **robots\_txt** :

    ```bash
    use auxiliary/scanner/http/robots_txt
    set PROXIES HTTP:127.0.0.1:8080
    ```
3.  Définissez la cible (RHOST) et le port (RPORT) :

    ```bash
    set RHOST SERVEUR_IP
    set RPORT PORT
    ```
4.  Lancez le module :

    ```bash
    run
    ```

**Résultat :**

```bash
bashCopy code[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

En revenant dans notre proxy, nous pourrons observer la requête dans l'historique. Cette méthode peut être utilisée avec d'autres scanners, exploits et fonctionnalités de Metasploit.
