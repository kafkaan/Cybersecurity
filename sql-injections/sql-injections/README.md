# SQL Injections

***

## <mark style="color:red;">Structured Query Language (SQL)</mark>

Le SQL suit une norme ISO mais la syntaxe varie selon les SGBD (ici on prend MySQL/MariaDB).\
Actions principales :

* Récupérer des données (SELECT)
* Mettre à jour des données (UPDATE)
* Supprimer des données (DELETE)
* Créer tables et bases (CREATE)
* Gérer les utilisateurs (ADD/CREATE USER, DROP USER)
* Attribuer permissions (GRANT / REVOKE)

***

### <mark style="color:blue;">Command Line</mark>

Le client `mysql` permet de se connecter et d’interagir avec MySQL/MariaDB.

* `-u` pour l’utilisateur, `-p` pour le mot de passe.
* Passe `-p` sans valeur (ex. `-p`) pour être invité à saisir le mot de passe — ne le met pas en clair dans la ligne de commande (évite qu’il reste dans l’historique).

```shell-session
mrroboteLiot@htb[/htb]$ mysql -u root -p
```

**Ou**

```shell-session
mrroboteLiot@htb[/htb]$ mysql -u root -p<password>
```

* Pas d’espace entre `-p` et le mot de passe si tu le fournis sur la ligne (mais évite de le faire).
* Les exemples utilisent `root/password` (superutilisateur) avec tous les privilèges — les autres utilisateurs ont des droits limités.
* Voir ses droits : `SHOW GRANTS;`.
* Par défaut la cible est `localhost`.
* Utiliser `-h <host>` et `-P <port>` pour se connecter à un hôte/port distant.

```shell-session
mrroboteLiot@htb[/htb]$ mysql -u root -h docker.hackthebox.eu -P 3306 -p 
```

***

### <mark style="color:blue;">Creating a database</mark>

```shell-session
mysql> CREATE DATABASE users;
```

* Les requêtes MySQL doivent finir par `;`.
* Exemple : création d’une base `users`.
* Lister les bases : `SHOW DATABASES;`.
* Changer de base : `USE users;`.

```shell-session
mysql> SHOW DATABASES;

mysql> USE users;

Database changed
```

***

### <mark style="color:blue;">Tables</mark>

* Un **SGBD** stocke les données sous forme de **tables**.
* Une table = lignes (rows) + colonnes (columns).
* Intersection = **cellule**.
* Chaque colonne a un type de donnée défini.

```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );
```

```shell-session
mysql> CREATE TABLE logins (
    ->     id INT,
    ->     username VARCHAR(100),
    ->     password VARCHAR(100),
    ->     date_of_joining DATETIME
    ->     );
Query OK, 0 rows affected (0.03 sec)
```

```shell-session
mysql> SHOW TABLES;
```

A list of tables in the current database can be obtained using the `SHOW TABLES` statement. In addition, the [DESCRIBE](https://dev.mysql.com/doc/refman/8.0/en/describe.html) keyword is used to list the table structure with its fields and data types.

```shell-session
mysql> DESCRIBE logins;
```

<mark style="color:green;">**Table Properties**</mark>

* Avec `CREATE TABLE`, on peut définir des propriétés pour la table et ses colonnes.
* Exemple : `AUTO_INCREMENT` sur une colonne `id` pour incrémenter automatiquement à chaque insertion.

```sql
    id INT NOT NULL AUTO_INCREMENT,
```

* `NOT NULL` : empêche une colonne d’être vide (champ obligatoire).
* `UNIQUE` : garantit que les valeurs sont uniques (ex. aucun doublon de `username`).

```sql
    username VARCHAR(100) UNIQUE NOT NULL,
```

* `DEFAULT` : définit une valeur par défaut pour une colonne.
* Exemple : `date_of_joining DEFAULT NOW()` pour utiliser la date et l’heure actuelles.

```sql
    date_of_joining DATETIME DEFAULT NOW(),
```

* `PRIMARY KEY` : identifie de façon unique chaque enregistrement d’une table.
* Exemple : définir la colonne `id` comme clé primaire.

```sql
    PRIMARY KEY (id)
```

The final `CREATE TABLE` query will be as follows:

```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
```

***

## <mark style="color:red;">**Les Principales Commandes SQL**</mark>

<mark style="color:green;">**1. INSERT (Ajouter des données)**</mark>

```sql
INSERT INTO table_name VALUES (valeur1, valeur2, ...);
```

*   Insérer des valeurs spécifiques à certaines colonnes :

    ```sql
    INSERT INTO table_name(colonne1, colonne2) VALUES (valeur1, valeur2);
    ```
*   Insérer plusieurs lignes :

    ```sql
    INSERT INTO table_name VALUES (valeur1, valeur2), (valeur3, valeur4);
    ```

<mark style="color:green;">**2. SELECT (Lire des données)**</mark>

*   Sélectionner toutes les colonnes :

    ```sql
    SELECT * FROM table_name;
    ```
*   Sélectionner des colonnes spécifiques :

    ```sql
    SELECT colonne1, colonne2 FROM table_name;
    ```

<mark style="color:green;">**3. DROP (Supprimer des tables ou bases)**</mark>

*   Supprimer une table :

    ```sql
    DROP TABLE table_name;
    ```

⚠️ **Attention** : La suppression est irréversible !

<mark style="color:green;">**4. ALTER (Modifier la structure d’une table)**</mark>

*   Ajouter une colonne :

    ```sql
    ALTER TABLE table_name ADD colonne_nom TYPE;
    ```
*   Renommer une colonne :

    ```sql
    ALTER TABLE table_name RENAME COLUMN ancien_nom TO nouveau_nom;
    ```
*   Modifier le type d’une colonne :

    ```sql
    ALTER TABLE table_name MODIFY colonne_nom TYPE;
    ```
*   Supprimer une colonne :

    ```sql
    ALTER TABLE table_name DROP colonne_nom;
    ```

<mark style="color:green;">**5. UPDATE (Mettre à jour des données)**</mark>

```sql
UPDATE table_name SET colonne1 = nouvelle_valeur1 WHERE condition;
```

*   Exemple :

    ```sql
    UPDATE logins SET password = 'new_pass' WHERE id > 1;
    ```

**Notes Importantes :**

* Utiliser toujours une clause **WHERE** avec `UPDATE` pour éviter de modifier toutes les données accidentellement.
* Les mots de passe ne doivent jamais être stockés en clair, mais doivent être **hachés** ou **cryptés**.

***

## <mark style="color:red;">Query Results</mark>

***

### <mark style="color:blue;">Sorting Results</mark>

We can sort the results of any query using [ORDER BY](https://dev.mysql.com/doc/refman/8.0/en/order-by-optimization.html) and specifying the column to sort by:

```shell-session
mysql> SELECT * FROM logins ORDER BY password;
```

By default, the sort is done in ascending order, but we can also sort the results by `ASC` or `DESC`:

```shell-session
mysql> SELECT * FROM logins ORDER BY password DESC;
```

It is also possible to sort by multiple columns, to have a secondary sort for duplicate values in one column:

```shell-session
mysql> SELECT * FROM logins ORDER BY password DESC, id ASC;
```

***

### <mark style="color:blue;">LIMIT results</mark>

In case our query returns a large number of records, we can [LIMIT](https://dev.mysql.com/doc/refman/8.0/en/limit-optimization.html) the results to what we want only, using `LIMIT` and the number of records we want:

```shell-session
mysql> SELECT * FROM logins LIMIT 2;
```

If we wanted to LIMIT results with an offset, we could specify the offset before the LIMIT count:

```shell-session
mysql> SELECT * FROM logins LIMIT 1, 2;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

Note: the offset marks the order of the first record to be included, starting from 0. For the above, it starts and includes the 2nd record, and returns two values.

***

### <mark style="color:blue;">WHERE Clause</mark>

To filter or search for specific data, we can use conditions with the `SELECT` statement using the [WHERE](https://dev.mysql.com/doc/refman/8.0/en/where-optimization.html) clause, to fine-tune the results:

```sql
SELECT * FROM table_name WHERE <condition>;
```

```shell-session
mysql> SELECT * FROM logins WHERE id > 1;
```

```shell-session
mysql> SELECT * FROM logins where username = 'admin';
```

**Note: String and date data types should be surrounded by single quote (') or double quotes ("), while numbers can be used directly.**

***

### <mark style="color:blue;">LIKE Clause</mark>

Another useful SQL clause is [LIKE](https://dev.mysql.com/doc/refman/8.0/en/pattern-matching.html), enabling selecting records by matching a certain pattern. The query below retrieves all records with usernames starting with `admin`:

```shell-session
mysql> SELECT * FROM logins WHERE username LIKE 'admin%';
```

The `%` symbol acts as a wildcard and matches all characters after `admin`. It is used to match zero or more characters. Similarly, the `_` symbol is used to match exactly one character. The below query matches all usernames with exactly three characters in them, which in this case was `tom`:

```shell-session
mysql> SELECT * FROM logins WHERE username like '___';
```
