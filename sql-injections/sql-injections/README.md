# SQL Injections

***

## <mark style="color:red;">Structured Query Language (SQL)</mark>

SQL syntax can differ from one RDBMS to another. However, they are all required to follow the [ISO standard](https://en.wikipedia.org/wiki/ISO/IEC_9075) for Structured Query Language. We will be following the MySQL/MariaDB syntax for the examples shown. SQL can be used to perform the following actions:

* Retrieve data
* Update data
* Delete data
* Create new tables and databases
* Add / remove users
* Assign permissions to these users

***

### <mark style="color:blue;">Command Line</mark>

The `mysql` utility is used to authenticate to and interact with a MySQL/MariaDB database. The `-u` flag is used to supply the username and the `-p` flag for the password. The `-p` flag should be passed empty, so we are prompted to enter the password and do not pass it directly on the command line since it could be stored in cleartext in the bash\_history file.

```shell-session
mrroboteLiot@htb[/htb]$ mysql -u root -p
```

Again, it is also possible to use the password directly in the command, though this should be avoided, as it could lead to the password being kept in logs and terminal history:

```shell-session
mrroboteLiot@htb[/htb]$ mysql -u root -p<password>
```

<mark style="color:orange;">**Tip: There shouldn't be any spaces between '-p' and the password.**</mark>

The examples above log us in as the superuser, i.e.,"`root`" with the password "`password`," to have privileges to execute all commands. Other DBMS users would have certain privileges to which statements they can execute. We can view which privileges we have using the [SHOW GRANTS](https://dev.mysql.com/doc/refman/8.0/en/show-grants.html) command which we will be discussing later.

When we do not specify a host, it will default to the `localhost` server. We can specify a remote host and port using the `-h` and `-P` flags.

```shell-session
mrroboteLiot@htb[/htb]$ mysql -u root -h docker.hackthebox.eu -P 3306 -p 
```

Note: The default MySQL/MariaDB port is (3306), but it can be configured to another port. It is specified using an uppercase \`P\`, unlike the lowercase \`p\` used for passwords.

***

### <mark style="color:blue;">Creating a database</mark>

Once we log in to the database using the `mysql` utility, we can start using SQL queries to interact with the DBMS. For example, a new database can be created within the MySQL DBMS using the [CREATE DATABASE](https://dev.mysql.com/doc/refman/5.7/en/create-database.html) statement.

```shell-session
mysql> CREATE DATABASE users;
```

MySQL expects command-line queries to be terminated with a semi-colon. The example above created a new database named `users`. We can view the list of databases with [SHOW DATABASES](https://dev.mysql.com/doc/refman/8.0/en/show-databases.html), and we can switch to the `users` database with the `USE` statement:

```shell-session
mysql> SHOW DATABASES;

mysql> USE users;

Database changed
```

***

### <mark style="color:blue;">Tables</mark>

DBMS stores data in the form of tables. A table is made up of horizontal rows and vertical columns. The intersection of a row and a column is called a cell. Every table is created with a fixed set of columns, where each column is of a particular data type.

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

Within the `CREATE TABLE` query, there are many [properties](https://dev.mysql.com/doc/refman/8.0/en/create-table.html) that can be set for the table and each column. For example, we can set the `id` column to auto-increment using the `AUTO_INCREMENT` keyword, which automatically increments the id by one every time a new item is added to the table:

```sql
    id INT NOT NULL AUTO_INCREMENT,
```

The `NOT NULL` constraint ensures that a particular column is never left empty 'i.e., required field.' We can also use the `UNIQUE` constraint to ensures that the inserted item are always unique. For example, if we use it with the `username` column, we can ensure that no two users will have the same username:

```sql
    username VARCHAR(100) UNIQUE NOT NULL,
```

Another important keyword is the `DEFAULT` keyword, which is used to specify the default value. For example, within the `date_of_joining` column, we can set the default value to [Now()](https://dev.mysql.com/doc/refman/8.0/en/date-and-time-functions.html#function_now), which in MySQL returns the current date and time:

```sql
    date_of_joining DATETIME DEFAULT NOW(),
```

Finally, one of the most important properties is `PRIMARY KEY`, which we can use to uniquely identify each record in the table, referring to all data of a record within a table for relational databases, as previously discussed in the previous section. We can make the `id` column the `PRIMARY KEY` for this table:

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

Permet d'insérer de nouvelles lignes dans une table.\
**Syntaxe** :

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

Permet de récupérer des données d’une table.\
**Syntaxe** :

*   Sélectionner toutes les colonnes :

    ```sql
    SELECT * FROM table_name;
    ```
*   Sélectionner des colonnes spécifiques :

    ```sql
    SELECT colonne1, colonne2 FROM table_name;
    ```

<mark style="color:green;">**3. DROP (Supprimer des tables ou bases)**</mark>

Supprime définitivement une table ou une base.\
**Syntaxe** :

*   Supprimer une table :

    ```sql
    DROP TABLE table_name;
    ```

⚠️ **Attention** : La suppression est irréversible !

<mark style="color:green;">**4. ALTER (Modifier la structure d’une table)**</mark>

Permet de modifier une table existante (ajouter, renommer ou supprimer des colonnes).\
**Syntaxes** :

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

Permet de modifier des enregistrements dans une table.\
**Syntaxe** :

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

Code: sql

```sql
SELECT * FROM table_name WHERE <condition>;
```

The query above will return all records which satisfy the given condition. Let us look at an example:

```shell-session
mysql> SELECT * FROM logins WHERE id > 1;
```

The example above selects all records where the value of `id` is greater than `1`. As we can see, the first row with its `id` as 1 was skipped from the output. We can do something similar for usernames:

```shell-session
mysql> SELECT * FROM logins where username = 'admin';
```

The query above selects the record where the username is `admin`. We can use the `UPDATE` statement to update certain records that meet a specific condition.

Note: String and date data types should be surrounded by single quote (') or double quotes ("), while numbers can be used directly.

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
