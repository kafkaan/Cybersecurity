# Medusa : Brute-Force Login Tool

**Medusa** est un outil rapide, massivement parallèle et modulaire permettant de tester la sécurité des systèmes d'authentification. Son objectif principal est de vérifier la robustesse des identifiants d'accès à distance.

***

#### <mark style="color:green;">**Installation**</mark>

*   Vérifier si Medusa est installé :

    ```bash
    medusa -h
    ```
*   Installation sur une distribution Linux :

    ```bash
    sudo apt-get -y update
    sudo apt-get -y install medusa
    ```

***

#### <mark style="color:green;">**Syntaxe Générale**</mark>

```bash
medusa [options_cibles] [options_identifiants] -M module [options_module]
```

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Paramètre</strong></td><td><strong>Description</strong></td><td><strong>Exemple</strong></td></tr><tr><td><code>-h HOST</code> ou <code>-H FILE</code></td><td>Cible unique ou liste de cibles.</td><td><code>medusa -h 192.168.1.10</code> ou <code>medusa -H targets.txt</code></td></tr><tr><td><code>-u USERNAME</code> ou <code>-U FILE</code></td><td>Nom d'utilisateur unique ou fichier contenant une liste d'utilisateurs.</td><td><code>medusa -u admin</code> ou <code>medusa -U users.txt</code></td></tr><tr><td><code>-p PASSWORD</code> ou <code>-P FILE</code></td><td>Mot de passe unique ou fichier contenant une liste de mots de passe.</td><td><code>medusa -p password123</code> ou <code>medusa -P passwords.txt</code></td></tr><tr><td><code>-M MODULE</code></td><td>Module utilisé pour l'attaque (e.g., ssh, ftp, http).</td><td><code>medusa -M ssh</code></td></tr><tr><td><code>-m "OPTION"</code></td><td>Options spécifiques au module, entre guillemets.</td><td><code>medusa -M http -m "POST /login.php ..."</code></td></tr><tr><td><code>-t TASKS</code></td><td>Nombre de tentatives parallèles.</td><td><code>medusa -t 4</code></td></tr><tr><td><code>-f</code> ou <code>-F</code></td><td>Arrêt dès la première réussite sur une cible (-f) ou sur toutes (-F).</td><td><code>medusa -f</code> ou <code>medusa -F</code></td></tr><tr><td><code>-n PORT</code></td><td>Port personnalisé pour le service cible.</td><td><code>medusa -n 2222</code></td></tr><tr><td><code>-v LEVEL</code></td><td>Niveau de verbosité (0 à 6).</td><td><code>medusa -v 4</code></td></tr></tbody></table>

***

#### <mark style="color:green;">**Modules Disponibles**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Module</strong></td><td><strong>Service/Protocole</strong></td><td><strong>Description</strong></td><td><strong>Exemple</strong></td></tr><tr><td><code>FTP</code></td><td>File Transfer Protocol</td><td>Brute-force des identifiants FTP.</td><td><code>medusa -M ftp -h 192.168.1.10 -u admin -P passwords.txt</code></td></tr><tr><td><code>HTTP</code></td><td>Hypertext Transfer Protocol</td><td>Brute-force des formulaires web.</td><td><code>medusa -M http -h www.example.com -U users.txt -P passwords.txt</code></td></tr><tr><td><code>SSH</code></td><td>Secure Shell</td><td>Brute-force des identifiants SSH.</td><td><code>medusa -M ssh -h 192.168.1.10 -u root -P passwords.txt</code></td></tr><tr><td><code>MySQL</code></td><td>Base de données MySQL</td><td>Brute-force des identifiants MySQL.</td><td><code>medusa -M mysql -h 192.168.1.10 -u root -P passwords.txt</code></td></tr><tr><td><code>POP3</code></td><td>Post Office Protocol 3</td><td>Brute-force des identifiants email (POP3).</td><td><code>medusa -M pop3 -h mail.example.com -U users.txt -P passwords.txt</code></td></tr><tr><td><code>RDP</code></td><td>Remote Desktop Protocol</td><td>Brute-force des identifiants RDP.</td><td><code>medusa -M rdp -h 192.168.1.10 -u admin -P passwords.txt</code></td></tr><tr><td><code>Telnet</code></td><td>Telnet Protocol</td><td>Brute-force des identifiants Telnet.</td><td><code>medusa -M telnet -h 192.168.1.10 -u admin -P passwords.txt</code></td></tr></tbody></table>

***

#### <mark style="color:green;">**Cas d’Utilisation**</mark>

**1. Tester un Serveur SSH**

Tester un serveur SSH sur `192.168.0.100` avec une liste d'utilisateurs et mots de passe :

```bash
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh
```

**2. Tester Plusieurs Serveurs HTTP**

Tester une liste de serveurs web protégés par authentification HTTP Basic :

```bash
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
```

**3. Tester des Mots de Passe Vides ou Défaut**

Vérifier si un hôte accepte des mots de passe vides ou identiques aux noms d'utilisateur :

```bash
medusa -h 10.0.0.5 -U usernames.txt -e ns -M service_name
```

***

#### <mark style="color:green;">**Avantages**</mark>

* **Rapidité** : Exécute plusieurs tâches simultanément.
* **Modularité** : Compatible avec de nombreux services d'authentification.
* **Personnalisation** : Permet des attaques très spécifiques grâce aux options des modules.

***

