# Using Comments

***

### <mark style="color:red;">Comments</mark>

* SQL permet d’utiliser des **commentaires** pour documenter ou ignorer une partie d’une requête.
* Types de commentaires MySQL :
  * Ligne : `--` ou `#`
  * Inline : `/* ... */` (rare en injection SQL)

```shell-session
mysql> SELECT username FROM logins; -- Selects usernames from the logins table 
```

* Pour démarrer un commentaire avec `--`, il faut **un espace après** : `--` (parfois encodé en URL `--+`).
* On peut aussi utiliser `#` pour commenter.

{% code fullWidth="true" %}
```shell-session
mysql> SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'
```
{% endcode %}

{% hint style="warning" %}
Tip: if you are inputting your payload in the URL within a browser, a (#) symbol is usually considered as a tag, and will not be passed as part of the URL. In order to use (#) as a comment within a browser, we can use '%23', which is an URL encoded (#) symbol.
{% endhint %}

The server will ignore the part of the query with `AND password = 'something'` during evaluation.

***

### <mark style="color:red;">Auth Bypass with comments</mark>

Let us go back to our previous example and inject **`admin'--`** as our username. The final query will be:

```sql
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
```

![admin\_dash](https://academy.hackthebox.com/storage/modules/33/admin_dash.png)

***

### <mark style="color:red;">Another Example</mark>

* SQL permet d’utiliser des **parenthèses** pour prioriser certaines conditions.
* Les expressions entre parenthèses sont évaluées **avant les autres opérateurs**.

![paranthesis\_fail](https://academy.hackthebox.com/storage/modules/33/paranthesis_fail.png)

* La requête force `id > 1`, empêchant de se connecter en tant qu’admin.
* Le **mot de passe est haché** avant d’être utilisé, bloquant l’injection via ce champ.
* Test avec des identifiants valides (`admin / p@ssw0rd`) pour observer la réponse

![paranthesis\_valid\_fail](https://academy.hackthebox.com/storage/modules/33/paranthesis_valid_fail.png)

* Le login échoue même avec des identifiants valides si l’**ID de l’admin = 1**.
* Essayer avec un autre utilisateur, par exemple `tom`.

![tom\_login](https://academy.hackthebox.com/storage/modules/33/tom_login.png)

* La connexion avec un utilisateur dont l’ID ≠ 1 fonctionne.
* Pour se connecter en tant qu’admin, on peut **commenter le reste de la requête**.
* Exemple d’injection : `admin'--` comme nom d’utilisateur.

![paranthesis\_error](https://academy.hackthebox.com/storage/modules/33/paranthesis_error.png)

{% hint style="danger" %}
The login failed due to a syntax error, as a closed one did not balance the open parenthesis. To execute the query successfully, we will have to add a closing parenthesis. Let us try using the username **`admin')--`** to close and comment out the rest.
{% endhint %}

![paranthesis\_success](https://academy.hackthebox.com/storage/modules/33/paranthesis_success.png)

The query was successful, and we logged in as admin. The final query as a result of our input is:

```sql
SELECT * FROM logins where (username='admin')
```
