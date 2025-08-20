# Using Comments

***

### <mark style="color:red;">Comments</mark>

Just like any other language, SQL allows the use of comments as well. Comments are used to document queries or ignore a certain part of the query. We can use two types of line comments with MySQL `--` and `#`, in addition to an in-line comment `/**/` (though this is not usually used in SQL injections). The `--` can be used as follows:

```shell-session
mysql> SELECT username FROM logins; -- Selects usernames from the logins table 
```

Note: In SQL, using two dashes only is not enough to start a comment. So, there has to be an empty space after them, so the comment starts with (-- ), with a space at the end. This is sometimes URL encoded as (--+), as spaces in URLs are encoded as (+). To make it clear, we will add another (-) at the end (-- -), to show the use of a space character.

The `#` symbol can be used as well.

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

As we see, we were able to bypass the authentication, as the new modified query checks for the username, with no other conditions.

***

### <mark style="color:red;">Another Example</mark>

SQL supports the usage of parenthesis if the application needs to check for particular conditions before others. Expressions within the parenthesis take precedence over other operators and are evaluated first. Let us look at a scenario like this:

![paranthesis\_fail](https://academy.hackthebox.com/storage/modules/33/paranthesis_fail.png)

The above query ensures that the user's id is always greater than 1, which will prevent anyone from logging in as admin. Additionally, we also see that the password was hashed before being used in the query. This will prevent us from injecting through the password field because the input is changed to a hash.

Let us try logging in with valid credentials `admin / p@ssw0rd` to see the response.

![paranthesis\_valid\_fail](https://academy.hackthebox.com/storage/modules/33/paranthesis_valid_fail.png)

As expected, the login failed even though we supplied valid credentials because the admin’s ID equals 1. So let us try logging in with the credentials of another user, such as `tom`.

![tom\_login](https://academy.hackthebox.com/storage/modules/33/tom_login.png)

Logging in as the user with an id not equal to 1 was successful. So, how can we log in as the admin? We know from the previous section on comments that we can use them to comment out the rest of the query. So, let us try using `admin'--` as the username.

![paranthesis\_error](https://academy.hackthebox.com/storage/modules/33/paranthesis_error.png)

{% hint style="danger" %}
The login failed due to a syntax error, as a closed one did not balance the open parenthesis. To execute the query successfully, we will have to add a closing parenthesis. Let us try using the username **`admin')--`** to close and comment out the rest.
{% endhint %}

![paranthesis\_success](https://academy.hackthebox.com/storage/modules/33/paranthesis_success.png)

The query was successful, and we logged in as admin. The final query as a result of our input is:

```sql
SELECT * FROM logins where (username='admin')
```

The query above is like the one from the previous example and returns the row containing admin.
