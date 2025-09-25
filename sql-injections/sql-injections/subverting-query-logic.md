# Subverting Query Logic

***

### <mark style="color:red;">Authentication Bypass</mark>

![admin\_panel](https://academy.hackthebox.com/storage/modules/33/admin_panel.png)

We can log in with the administrator credentials `admin / p@ssw0rd`.

![admin\_creds](https://academy.hackthebox.com/storage/modules/33/admin_creds.png)

```sql
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
```

* La page utilise les **identifiants** et l’opérateur `AND` pour chercher un enregistrement correspondant à `username` et `password`.
* Si un enregistrement est trouvé → identifiants valides → login accepté.
* Sinon, si les identifiants sont incorrects, la condition est fausse → login refusé.

![admin\_incorrect](https://academy.hackthebox.com/storage/modules/33/admin_incorrect.png)

***

### <mark style="color:red;">SQLi Discovery</mark>

* Avant de contourner l’authentification, il faut tester si le formulaire de login est **vulnérable à l’injection SQL**.
* Pour cela, on ajoute un **payload** après le `username` et on observe si la page génère une erreur ou se comporte différemment.

| Payload | URL Encoded |
| ------- | ----------- |
| `'`     | `%27`       |
| `"`     | `%22`       |
| `#`     | `%23`       |
| `;`     | `%3B`       |
| `)`     | `%29`       |

![quote\_error](https://academy.hackthebox.com/storage/modules/33/quote_error.png)

We see that a SQL error was thrown instead of the `Login Failed` message. The page threw an error because the resulting query was:

```sql
SELECT * FROM logins WHERE username=''' AND password = 'something';
```

* Une quote mal placée peut provoquer une **erreur de syntaxe**.
* Solutions :
  1. **Commenter** le reste de la requête et compléter avec notre injection.
  2. Utiliser un **nombre pair de quotes** pour que la requête finale reste valide.

***

### <mark style="color:red;">OR Injection</mark>

* Pour **bypasser l’authentification**, il faut que la requête renvoie toujours `TRUE`, peu importe les identifiants.
* On peut exploiter l’opérateur **OR** : si une condition est vraie, la requête complète devient vraie.
* Exemple de condition toujours vraie : `'1'='1'`.
* Pour garder un **nombre pair de quotes**, on adapte l’injection (`'1'='1`) afin que la requête reste valide

```sql
admin' or '1'='1
```

```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```

![or\_inject\_diagram](https://academy.hackthebox.com/storage/modules/33/or_inject_diagram.png)

{% hint style="warning" %}
Note: The payload we used above is one of many auth bypass payloads we can use to subvert the authentication logic. You can find a comprehensive list of SQLi auth bypass payloads in [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass), each of which works on a certain type of SQL queries.

***
{% endhint %}

***

### <mark style="color:red;">Auth Bypass with OR operator</mark>

<figure><img src="https://academy.hackthebox.com/storage/modules/33/inject_success.png" alt=""><figcaption></figcaption></figure>

We were able to log in successfully as admin. However, what if we did not know a valid username? Let us try the same request with a different username this time.

![notadmin\_fail](https://academy.hackthebox.com/storage/modules/33/notadmin_fail.png)

The login failed because `notAdmin` does not exist in the table and resulted in a false query overall.

<div align="center"><img src="https://academy.hackthebox.com/storage/modules/33/notadmin_diagram_1.png" alt="notadmin_diagram"></div>

![password\_or\_injection](https://academy.hackthebox.com/storage/modules/33/password_or_injection.png)

The additional `OR` condition resulted in a `true` query overall, as the `WHERE` clause returns everything in the table, and the user present in the first row is logged in. In this case, as both conditions will return `true`, we do not have to provide a test username and password and can directly start with the `'` injection and log in with just `' or '1' = '1`.

![basic\_auth\_bypass](https://academy.hackthebox.com/storage/modules/33/basic_auth_bypass.png)
