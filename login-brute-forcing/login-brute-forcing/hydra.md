# Hydra

***

Hydra is a fast network login cracker that supports numerous attack protocols. It is a versatile tool that can brute-force a wide range of services, including web applications, remote login services like SSH and FTP, and even databases.

* `Speed and Efficiency`: Hydra utilizes parallel connections to perform multiple login attempts simultaneously, significantly speeding up the cracking process.
* `Flexibility`: Hydra supports many protocols and services, making it adaptable to various attack scenarios.
* `Ease of Use`: Hydra is relatively easy to use despite its power, with a straightforward command-line interface and clear syntax.

## <mark style="color:red;">Installation</mark>

Hydra often comes pre-installed on popular penetration testing distributions. You can verify its presence by running:

```shell-session
mrroboteLiot@htb[/htb]$ hydra -h
```

If Hydra is not installed or you are using a different Linux distribution, you can install it from the package repository:

```shell-session
mrroboteLiot@htb[/htb]$ sudo apt-get -y update
mrroboteLiot@htb[/htb]$ sudo apt-get -y install hydra 
```

***

## <mark style="color:red;">Basic Usage</mark>

Hydra's basic syntax is:

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hydra [login_options] [password_options] [attack_options] [service_options]
```
{% endcode %}

<table data-full-width="true"><thead><tr><th>Parameter</th><th>Explanation</th><th>Usage Example</th></tr></thead><tbody><tr><td><code>-l LOGIN</code> or <code>-L FILE</code></td><td>Login options: Specify either a single username (<code>-l</code>) or a file containing a list of usernames (<code>-L</code>).</td><td><code>hydra -l admin ...</code> or <code>hydra -L usernames.txt ...</code></td></tr><tr><td><code>-p PASS</code> or <code>-P FILE</code></td><td>Password options: Provide either a single password (<code>-p</code>) or a file containing a list of passwords (<code>-P</code>).</td><td><code>hydra -p password123 ...</code> or <code>hydra -P passwords.txt ...</code></td></tr><tr><td><code>-t TASKS</code></td><td>Tasks: Define the number of parallel tasks (threads) to run, potentially speeding up the attack.</td><td><code>hydra -t 4 ...</code></td></tr><tr><td><code>-f</code></td><td>Fast mode: Stop the attack after the first successful login is found.</td><td><code>hydra -f ...</code></td></tr><tr><td><code>-s PORT</code></td><td>Port: Specify a non-default port for the target service.</td><td><code>hydra -s 2222 ...</code></td></tr><tr><td><code>-v</code> or <code>-V</code></td><td>Verbose output: Display detailed information about the attack's progress, including attempts and results.</td><td><code>hydra -v ...</code> or <code>hydra -V ...</code> (for even more verbosity)</td></tr><tr><td><code>service://server</code></td><td>Target: Specify the service (e.g., <code>ssh</code>, <code>http</code>, <code>ftp</code>) and the target server's address or hostname.</td><td><code>hydra ssh://192.168.1.100</code></td></tr><tr><td><code>/OPT</code></td><td>Service-specific options: Provide any additional options required by the target service.</td><td><code>hydra http-get://example.com/login.php -m "POST:user=^USER^&#x26;pass=^PASS^"</code> (for HTTP form-based authentication)</td></tr></tbody></table>

***

<mark style="color:green;">**Hydra Services**</mark>

Hydra services essentially define the specific protocols or services that Hydra can target. They enable Hydra to interact with different authentication mechanisms used by various systems, applications, and network services.

<table data-full-width="true"><thead><tr><th width="185">Hydra Service</th><th width="199">Service/Protocol</th><th width="203">Description</th><th>Example Command</th></tr></thead><tbody><tr><td>ftp</td><td>File Transfer Protocol (FTP)</td><td>Used to brute-force login credentials for FTP services, commonly used to transfer files over a network.</td><td><code>hydra -l admin -P /path/to/password_list.txt ftp://192.168.1.100</code></td></tr><tr><td>ssh</td><td>Secure Shell (SSH)</td><td>Targets SSH services to brute-force credentials, commonly used for secure remote login to systems.</td><td><code>hydra -l root -P /path/to/password_list.txt ssh://192.168.1.100</code></td></tr><tr><td>http-get/post</td><td>HTTP Web Services</td><td>Used to brute-force login credentials for HTTP web login forms using either GET or POST requests.</td><td><code>hydra -l admin -P /path/to/password_list.txt http-post-form "/login.php:user=^USER^&#x26;pass=^PASS^:F=incorrect"</code></td></tr><tr><td>smtp</td><td>Simple Mail Transfer Protocol</td><td>Attacks email servers by brute-forcing login credentials for SMTP, commonly used to send emails.</td><td><code>hydra -l admin -P /path/to/password_list.txt smtp://mail.server.com</code></td></tr><tr><td>pop3</td><td>Post Office Protocol (POP3)</td><td>Targets email retrieval services to brute-force credentials for POP3 login.</td><td><code>hydra -l user@example.com -P /path/to/password_list.txt pop3://mail.server.com</code></td></tr><tr><td>imap</td><td>Internet Message Access Protocol</td><td>Used to brute-force credentials for IMAP services, which allow users to access their email remotely.</td><td><code>hydra -l user@example.com -P /path/to/password_list.txt imap://mail.server.com</code></td></tr><tr><td>mysql</td><td>MySQL Database</td><td>Attempts to brute-force login credentials for MySQL databases.</td><td><code>hydra -l root -P /path/to/password_list.txt mysql://192.168.1.100</code></td></tr><tr><td>mssql</td><td>Microsoft SQL Server</td><td>Targets Microsoft SQL servers to brute-force database login credentials.</td><td><code>hydra -l sa -P /path/to/password_list.txt mssql://192.168.1.100</code></td></tr><tr><td>vnc</td><td>Virtual Network Computing (VNC)</td><td>Brute-forces VNC services, used for remote desktop access.</td><td><code>hydra -P /path/to/password_list.txt vnc://192.168.1.100</code></td></tr><tr><td>rdp</td><td>Remote Desktop Protocol (RDP)</td><td>Targets Microsoft RDP services for remote login brute-forcing.</td><td><code>hydra -l admin -P /path/to/password_list.txt rdp://192.168.1.100</code></td></tr></tbody></table>

***

#### <mark style="color:green;">Brute-Forcing HTTP Authentication</mark>

Imagine you're tasked with testing the security of a website using basic HTTP authentication at `www.example.com`. You have a list of potential usernames stored in `usernames.txt` and corresponding passwords in `passwords.txt`. To launch a brute-force attack against this HTTP service, use the following Hydra command:

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hydra -L usernames.txt -P passwords.txt www.example.com http-get
```
{% endcode %}

This command instructs Hydra to:

* Use the list of usernames from the `usernames.txt` file.
* Use the list of passwords from the `passwords.txt` file.
* Target the website `www.example.com`.
* Employ the `http-get` module to test the HTTP authentication.

Hydra will systematically try each username-password combination against the target website to discover a valid login.

***

#### <mark style="color:green;">Targeting Multiple SSH Servers</mark>

Consider a situation where you have identified several servers that may be vulnerable to SSH brute-force attacks. You compile their IP addresses into a file named `targets.txt` and know that these servers might use the default username "root" and password "toor." To efficiently test all these servers simultaneously, use the following Hydra command:

```shell-session
mrroboteLiot@htb[/htb]$ hydra -l root -p toor -M targets.txt ssh
```

This command instructs Hydra to:

* Use the username "root".
* Use the password "toor".
* Target all IP addresses listed in the `targets.txt` file.
* Employ the `ssh` module for the attack.

Hydra will execute parallel brute-force attempts on each server, significantly speeding up the process.

***

#### <mark style="color:green;">Testing FTP Credentials on a Non-Standard Port</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp.example.com ftp
```
{% endcode %}

This command instructs Hydra to:

* Use the list of usernames from the `usernames.txt` file.
* Use the list of passwords from the `passwords.txt` file.
* Target the FTP service on `ftp.example.com` via port `2121`.
* Use the `ftp` module and provide verbose output (`-V`) for detailed monitoring.

Hydra will attempt to match each username-password combination against the FTP server on the specified port.

***

#### <mark style="color:green;">Brute-Forcing a Web Login Form</mark>

Suppose you are tasked with brute-forcing a login form on a web application at `www.example.com`. You know the username is "admin," and the form parameters for the login are `user=^USER^&pass=^PASS^`. To perform this attack, use the following Hydra command:

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```
{% endcode %}

This command instructs Hydra to:

* Use the username "admin".
* Use the list of passwords from the `passwords.txt` file.
* Target the login form at `/login` on `www.example.com`.
* Employ the `http-post-form` module with the specified form parameters.
* Look for a successful login indicated by the HTTP status code `302`.

Hydra will systematically attempt each password for the "admin" account, checking for the specified success condition.

***

#### <mark style="color:green;">Advanced RDP Brute-Forcing</mark>

Now, imagine you're testing a Remote Desktop Protocol (RDP) service on a server with IP `192.168.1.100`. You suspect the username is "administrator," and that the password consists of 6 to 8 characters, including lowercase letters, uppercase letters, and numbers. To carry out this precise attack, use the following Hydra command:

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp
```
{% endcode %}

This command instructs Hydra to:

* Use the username "administrator".
* Generate and test passwords ranging from 6 to 8 characters, using the specified character set.
* Target the RDP service on `192.168.1.100`.
* Employ the `rdp` module for the attack.

Hydra will generate and test all possible password combinations within the specified parameters, attempting to break into the RDP service.
