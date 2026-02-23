---
cover: ../../../../.gitbook/assets/mysql.jpg
coverY: -96.225
---

# MySQL

## <mark style="color:red;">Introduction à MySQL</mark>

MySQL est un **système de gestion de bases de données relationnelles** (SGBDR) open-source, développé et soutenu par Oracle. Il utilise le langage SQL pour la gestion des données. MySQL fonctionne selon le principe client-serveur, avec un serveur MySQL qui gère la base de données et un ou plusieurs clients MySQL qui interagissent avec ce serveur.

***

## <mark style="color:red;">Fonctionnement de MySQL</mark>

* **Serveur MySQL** : Gère le stockage et la distribution des données.
* **Clients MySQL** : Utilisent des requêtes SQL pour insérer, supprimer, modifier et récupérer des données.
* **Tables** : Les données sont stockées dans des tables avec des colonnes, des lignes et des types de données différents. Les bases de données sont souvent stockées dans des fichiers avec l'extension `.sql` (par exemple, `wordpress.sql`).

***

## <mark style="color:red;">Clients MySQL</mark>

Les clients MySQL envoient des requêtes structurées au serveur pour interagir avec les bases de données. Ils peuvent effectuer des opérations telles que l'insertion, la suppression, la modification et la récupération de données.

#### <mark style="color:green;">Exemple d'utilisation</mark>

Un exemple typique est le CMS WordPress, qui stocke tous les articles, noms d'utilisateur et mots de passe dans une base de données accessible uniquement depuis localhost. D'autres structures de bases de données peuvent être distribuées sur plusieurs serveurs.

***

### <mark style="color:red;">Applications Typiques</mark>

MySQL est souvent utilisé pour des sites web dynamiques, en conjonction avec un système d'exploitation Linux, PHP, et un serveur web Apache (ensemble appelé LAMP) ou Nginx (LEMP). MySQL sert de source centrale pour les scripts PHP, stockant des informations telles que :

* Titres
* Textes
* Tags meta
* Formulaires
* Informations clients
* Emails
* Informations utilisateur
* Permissions
* Mots de passe
* Liens externes et internes
* Valeurs

***

### <mark style="color:red;">Commandes MySQL</mark>

Les commandes MySQL sont traduites en code exécutable et exécutent les actions demandées. En cas d'erreurs, des messages peuvent contenir des informations sensibles pouvant être exploitées. Les commandes SQL permettent de :

* Afficher, modifier, ajouter ou supprimer des lignes dans des tables.
* Changer la structure des tables, créer ou supprimer des relations et des index, et gérer les utilisateurs.

#### <mark style="color:green;">Commandes de base</mark>

* `mysql -u <user> -p<password> -h <IP address>` : Connexion au serveur MySQL.
* `show databases;` : Afficher toutes les bases de données.
* `use <database>;` : Sélectionner une base de données.
* `show tables;` : Afficher toutes les tables dans la base de données sélectionnée.
* `show columns from <table>;` : Afficher toutes les colonnes d'une table.
* `select * from <table>;` : Afficher toutes les données dans une table.
* `select * from <table> where <column> = "<string>";` : Rechercher une chaîne spécifique dans une table.

***

### <mark style="color:red;">Configuration par Défaut</mark>

#### <mark style="color:green;">Installation et Configuration de Base</mark>

```bash
sudo apt install mysql-server -y
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
```

Configuration typique :

```ini
[client]
port        = 3306
socket      = /var/run/mysqld/mysqld.sock

[mysqld_safe]
pid-file    = /var/run/mysqld/mysqld.pid
socket      = /var/run/mysqld/mysqld.sock
nice        = 0

[mysqld]
skip-host-cache
skip-name-resolve
user        = mysql
pid-file    = /var/run/mysqld/mysqld.pid
socket      = /var/run/mysqld/mysqld.sock
port        = 3306
basedir     = /usr
datadir     = /var/lib/mysql
tmpdir      = /tmp
lc-messages-dir = /usr/share/mysql
explicit_defaults_for_timestamp
symbolic-links=0
!includedir /etc/mysql/conf.d/
```

## <mark style="color:red;">Paramètres Sécuritaires</mark>

Certaines options de configuration sont particulièrement sensibles :

* `user` : Utilisateur sous lequel le service MySQL fonctionne.
* `password` : Mot de passe de l'utilisateur MySQL.
* `admin_address` : Adresse IP d'écoute pour les connexions TCP/IP.
* `debug` : Paramètres de débogage.
* `sql_warnings` : Affichage des avertissements lors d'opérations d'insertion.

Ces paramètres peuvent être critiques en cas de mauvaise configuration ou de droits mal attribués, exposant potentiellement les mots de passe et les informations sensibles.

***

### <mark style="color:blue;">Analyse et Sécurité</mark>

#### <mark style="color:green;">Scan de Port</mark>

**Le port TCP 3306** est généralement utilisé par MySQL. Utilisez `nmap` pour scanner ce port :

```bash
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```

#### <mark style="color:green;">Interaction avec le Serveur MySQL</mark>

Testez la connexion avec un mot de passe supposé :

```bash
mysql -u root -pP4SSw0rd -h 10.129.14.128
```

Some of the commands we should remember and write down for working with MySQL databases are described below in the table.

{% hint style="warning" %}
If we look at the existing databases, we will see several already exist. The most important databases for the MySQL server are the `system schema` (`sys`) and `information schema` (`information_schema`). The system schema contains tables, information, and metadata necessary for management. More about this database can be found in the [reference manual](https://dev.mysql.com/doc/refman/8.0/en/system-schema.html) of MySQL.
{% endhint %}

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Command</strong></td><td><strong>Description</strong></td></tr><tr><td><code>mysql -u &#x3C;user> -p&#x3C;password> -h &#x3C;IP address></code></td><td>Connect to the MySQL server. There should <strong>not</strong> be a space between the '-p' flag, and the password.</td></tr><tr><td><code>show databases;</code></td><td>Show all databases.</td></tr><tr><td><code>use &#x3C;database>;</code></td><td>Select one of the existing databases.</td></tr><tr><td><code>show tables;</code></td><td>Show all available tables in the selected database.</td></tr><tr><td><code>show columns from &#x3C;table>;</code></td><td>Show all columns in the selected database.</td></tr><tr><td><code>select * from &#x3C;table>;</code></td><td>Show everything in the desired table.</td></tr><tr><td><code>select * from &#x3C;table> where &#x3C;column> = "&#x3C;string>";</code></td><td>Search for needed <code>string</code> in the desired table.</td></tr></tbody></table>

{% hint style="warning" %}
<mark style="color:orange;">**Le schéma**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`sys`**</mark> est une base de données spéciale dans MySQL conçue pour faciliter la gestion et la surveillance du serveur de bases de données. Voici une explication détaillée de ce qu'est le schéma `sys` et comment il est utilisé, avec un exemple concret pour mieux comprendre.

***

<mark style="color:green;">**Qu'est-ce que le Schéma**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`sys`**</mark><mark style="color:green;">**?**</mark>

1. **Définition**
   * **`sys`** est une base de données intégrée à MySQL qui fournit des vues, des fonctions et des procédures stockées pour simplifier l'administration et la surveillance du serveur MySQL. Elle est conçue pour rendre les informations de gestion plus accessibles et plus compréhensibles.
2. **Contenu**
   * Le schéma `sys` contient des tables et des vues qui fournissent des informations sur l'état du serveur, les performances, et les opérations en cours. Par exemple, il peut afficher des statistiques sur les requêtes, les indices, et les verrous.
3. **Utilité**
   * Le schéma `sys` est particulièrement utile pour les administrateurs de bases de données, car il permet de surveiller et d'analyser le serveur de manière plus intuitive grâce à des vues simplifiées.

***

<mark style="color:green;">**Exemple d'Utilisation du Schéma**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`sys`**</mark>

Imaginons que vous souhaitez obtenir des informations sur les hôtes qui se connectent à votre serveur MySQL. Vous pouvez utiliser les tables du schéma `sys` pour obtenir ces informations de manière simplifiée.

1.  **Affichage des Tables dans `sys`**

    D'abord, connectez-vous à votre serveur MySQL et utilisez le schéma `sys` :

    ```sql
    USE sys;
    SHOW TABLES;
    ```

    Cette commande affiche toutes les tables disponibles dans le schéma `sys`.
2.  **Consulter la Table `host_summary`**

    Supposons que vous voulez voir un résumé des hôtes qui se connectent à votre serveur MySQL. Vous pouvez utiliser la table `host_summary` :

    ```sql
    SELECT * FROM host_summary;
    ```

    Cette commande affiche un résumé des connexions par hôte, y compris des statistiques sur le nombre d'utilisateurs uniques connectés.
3.  **Exemple de Résultat**

    Imaginons que vous obtenez le résultat suivant :

    ```plaintext
    +-------------+--------------+
    | host        | unique_users |
    +-------------+--------------+
    | 10.0.0.1    |            5 |
    | 192.168.1.10|            2 |
    | localhost   |            10|
    +-------------+--------------+
    ```

    * **`host`** : L'adresse IP ou le nom d'hôte des clients se connectant au serveur MySQL.
    * **`unique_users`** : Le nombre d'utilisateurs uniques connectés depuis cet hôte.
4.  **Exemple de Commande pour Obtenir des Détails sur les Verrous**

    Vous pouvez aussi consulter les verrous en cours d'utilisation pour diagnostiquer des problèmes de performance :

    ```sql
    SELECT * FROM innodb_lock_waits;
    ```

    Cette commande montre les verrous en cours et qui attend pour des ressources dans InnoDB.

***

<mark style="color:green;">**Comparaison avec le Schéma**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`information_schema`**</mark>

* **`information_schema`** : Ce schéma contient des vues d'information standardisées sur les bases de données, les tables, les colonnes, etc. Il est conforme aux normes ANSI/ISO SQL et est utilisé pour obtenir des informations détaillées sur les structures de la base de données.
* **`sys`** : Complète `information_schema` en fournissant des vues et des procédures spécifiques pour la gestion et la surveillance du serveur, souvent de manière plus conviviale.
{% endhint %}
