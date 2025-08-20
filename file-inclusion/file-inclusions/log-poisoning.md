# Log Poisoning

L'idée est d’**injecter du code PHP dans un champ que nous contrôlons**, tel qu’un **User-Agent**, une URL, ou un paramètre GET/POST, **qui sera ensuite enregistré dans un fichier de logs** du serveur (comme un fichier de logs Apache, Nginx ou PHP).

On parle alors de **"contamination" ou "empoisonnement" du fichier de log**.

Ensuite, si une **vulnérabilité de type LFI** est présente, on peut tenter d’**inclure ce fichier de log via LFI**, ce qui aura pour effet d’**exécuter le code PHP injecté** s’il n’a pas été échappé.

***

#### <mark style="color:green;">🧨 Conditions pour réussir l’attaque</mark>

1. L’application web **enregistre dans les logs une donnée contrôlable** (comme un header ou une URL).
2. Le fichier de log est **lisible par le serveur PHP** (permissions `www-data` ou équivalent).
3. Il existe une **LFI exploitable** qui permet d’inclure ce fichier de log.
4. Le serveur ne filtre pas ou n’échappe pas les caractères PHP (`<?php ... ?>`).

***

### <mark style="color:red;">PHP Session Poisoning</mark>

Most PHP web applications utilize `PHPSESSID` cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies.&#x20;

These details are stored in `session` files on the back-end, and saved in `/var/lib/php/sessions/` on Linux and in `C:\Windows\Temp\` on Windows.&#x20;

The name of the file that contains our user's data matches the name of our `PHPSESSID` cookie with the `sess_` prefix. For example, if the `PHPSESSID` cookie is set to `el4ukv0kqbvoirg7nkp4dncpk3`, then its location on disk would be `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`.

The first thing we need to do in a PHP Session Poisoning attack is to examine our PHPSESSID session file and see if it contains any data we can control and poison. So, let's first check if we have a `PHPSESSID` cookie set to our session:

<figure><img src="../../.gitbook/assets/image (115).png" alt=""><figcaption></figcaption></figure>

As we can see, our `PHPSESSID` cookie value is `nhhv8i0o6ua4g88bkdl9u1fdsd`, so it should be stored at `/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`. Let's try include this session file through the LFI vulnerability and view its contents:

<figure><img src="../../.gitbook/assets/image (116).png" alt=""><figcaption></figcaption></figure>

We can see that the session file contains two values: `page`, which shows the selected language page, and `preference`, which shows the selected language. The `preference` value is not under our control, as we did not specify it anywhere and must be automatically specified. However, the `page` value is under our control, as we can control it through the `?language=` parameter.

Let's try setting the value of `page` a custom value (e.g. `language parameter`) and see if it changes in the session file. We can do so by simply visiting the page with `?language=session_poisoning` specified, as follows:

```url
http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
```

Now, let's include the session file once again to look at the contents:

<figure><img src="../../.gitbook/assets/image (117).png" alt=""><figcaption></figcaption></figure>

This time, the session file contains `session_poisoning` instead of `es.php`, which confirms our ability to control the value of `page` in the session file. Our next step is to perform the `poisoning` step by writing PHP code to the session file. We can write a basic PHP web shell by changing the `?language=` parameter to a URL encoded web shell, as follows:

{% code overflow="wrap" fullWidth="true" %}
```url
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```
{% endcode %}

Finally, we can include the session file and use the `&cmd=id` to execute a commands:

http://\<SERVER\_IP>:/index.php?language=/var/lib/php/sessions/sess\_hvkg1jclhsqefaillf0gst31nm\&cmd=id

&#x20; &#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/23/rfi_session_id.png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
Note: To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten with `/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd` after our last inclusion. Ideally, we would use the poisoned web shell to write a permanent web shell to the web directory, or send a reverse shell for easier interaction.
{% endhint %}

***

### <mark style="color:red;">Server Log Poisoning</mark>

Both `Apache` and `Nginx` maintain various log files, such as `access.log` and `error.log`. The `access.log` file contains various information about all requests made to the server, including each request's `User-Agent` header. As we can control the `User-Agent` header in our requests, we can use it to poison the server logs as we did above.

Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have read-access over the logs. `Nginx` logs are readable by low privileged users by default (e.g. `www-data`), while the `Apache` logs are only readable by users with high privileges (e.g. `root`/`adm` groups). However, in older or misconfigured `Apache` servers, these logs may be readable by low-privileged users.

By default, `Apache` logs are located in `/var/log/apache2/` on Linux and in `C:\xampp\apache\logs\`&#x20;

on Windows, while `Nginx` logs are located in `/var/log/nginx/` on Linux and in `C:\nginx\log\` on Windows. However, the logs may be in a different location in some cases, so we may use an [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for their locations, as will be discussed in the next section.

So, let's try including the Apache access log from `/var/log/apache2/access.log`, and see what we get:

<figure><img src="../../.gitbook/assets/image (119).png" alt=""><figcaption></figcaption></figure>

As we can see, we can read the log. The log contains the `remote IP address`, `request page`, `response code`, and the `User-Agent` header. As mentioned earlier, the `User-Agent` header is controlled by us through the HTTP request headers, so we should be able to poison this value.

Tip: Logs tend to be huge, and loading them in an LFI vulnerability may take a while to load, or even crash the server in worst-case scenarios. So, be careful and efficient with them in a production environment, and don't send unnecessary requests.

To do so, we will use `Burp Suite` to intercept our earlier LFI request and modify the `User-Agent` header to `Apache Log Poisoning`:

<figure><img src="../../.gitbook/assets/image (120).png" alt=""><figcaption></figcaption></figure>

Note: As all requests to the server get logged, we can poison any request to the web application, and not necessarily the LFI one as we did above.

As expected, our custom User-Agent value is visible in the included log file. Now, we can poison the `User-Agent` header by setting it to a basic PHP web shell:&#x20;

<figure><img src="../../.gitbook/assets/image (121).png" alt=""><figcaption></figcaption></figure>

We may also poison the log by sending a request through cURL, as follows:

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
```
{% endcode %}

As the log should now contain PHP code, the LFI vulnerability should execute this code, and we should be able to gain remote code execution. We can specify a command to be executed with (`?cmd=id`):&#x20;

<figure><img src="../../.gitbook/assets/image (122).png" alt=""><figcaption></figcaption></figure>

We see that we successfully executed the command. The exact same attack can be carried out on `Nginx` logs as well.

{% hint style="danger" %}
Tip: The `User-Agent` header is also shown on process files under the Linux `/proc/` directory. So, we can try including the `/proc/self/environ` or `/proc/self/fd/N` files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. This may become handy in case we did not have read access over the server logs, however, these files may only be readable by privileged users as well.

Finally, there are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:

* `/var/log/sshd.log`
* `/var/log/mail`
* `/var/log/vsftpd.log`

We should first attempt reading these logs through LFI, and if we do have access to them, we can try to poison them as we did above. For example, if the `ssh` or `ftp` services are exposed to us, and we can read their logs through LFI, then we can try logging into them and set the username to PHP code, and upon including their logs, the PHP code would execute. The same applies the `mail` services, as we can send an email containing PHP code, and upon its log inclusion, the PHP code would execute. We can generalize this technique to any logs that log a parameter we control and that we can read through the LFI vulnerability.
{% endhint %}
