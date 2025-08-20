# Attacking FTP

***

### <mark style="color:blue;">Enumeration</mark>

`Nmap` default scripts `-sC` includes the [ftp-anon](https://nmap.org/nsedoc/scripts/ftp-anon.html) Nmap script which checks if a FTP server allows anonymous logins. The version enumeration flag `-sV` provides interesting information about FTP services, such as the FTP banner, which often includes the version name. We can use the `ftp` client or `nc` to interact with the FTP service. By default, FTP runs on TCP port 21.

<mark style="color:orange;">**Nmap**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo nmap -sC -sV -p 21 192.168.2.142 .
```

***

### <mark style="color:blue;">Misconfigurations</mark>

As we discussed, anonymous authentication can be configured for different services such as FTP. To access with anonymous login, we can use the `anonymous` username and no password. This will be dangerous for the company if read and write permissions have not been set up correctly for the FTP service. Because with the anonymous login, the company could have stored sensitive information in a folder that the anonymous user of the FTP service could have access to.

<mark style="color:orange;">**Anonymous Authentication**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ ftp 192.168.2.142    

```

To download a single file, we use `get`, and to download multiple files, we can use `mget`. For upload operations, we can use `put` for a simple file or `mput` for multiple files. We can use `help` in the FTP client session for more information.

***

### <mark style="color:blue;">Protocol Specifics Attacks</mark>

Many different attacks and methods are protocol-based. However, it is essential to note that we are not attacking the individual protocols themselves but the services that use them. Since there are dozens of services for a single protocol and they process the corresponding information differently, we will look at some.

#### <mark style="color:green;">**Brute Forcing**</mark>

If there is no anonymous authentication available, we can also brute-force the login for the FTP services using a list of the pre-generated usernames and passwords. There are many different tools to perform a brute-forcing attack. Let us explore one of them, [Medusa](https://github.com/jmk-foofus/medusa). With `Medusa`, we can use the option `-u` to specify a single user to target, or you can use the option `-U` to provide a file with a list of usernames. The option `-P` is for a file containing a list of passwords. We can use the option `-M` and the protocol we are targeting (FTP) and the option `-h` for the target hostname or IP address.

<mark style="color:orange;">**Brute Forcing with Medusa**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
```
{% endcode %}

#### <mark style="color:green;">**FTP Bounce Attack**</mark>

An FTP bounce attack is a network attack that uses FTP servers to deliver outbound traffic to another device on the network. The attacker uses a `PORT` command to trick the FTP connection into running commands and getting information from a device other than the intended server.

Consider we are targetting an FTP Server `FTP_DMZ` exposed to the internet. Another device within the same network, `Internal_DMZ`, is not exposed to the internet. We can use the connection to the `FTP_DMZ` server to scan `Internal_DMZ` using the FTP Bounce attack and obtain information about the server's open ports. Then, we can use that information as part of our attack against the infrastructure.

![text](https://academy.hackthebox.com/storage/modules/116/ftp_bounce_attack.png)

The `Nmap` -b flag can be used to perform an FTP bounce attack:

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```
{% endcode %}

***

### <mark style="color:blue;">Latest FTP Vulnerabilities</mark>

***

In this case, we will discuss the `CoreFTP before build 727` vulnerability assigned [CVE-2022-22836](https://nvd.nist.gov/vuln/detail/CVE-2022-22836). This vulnerability is for an FTP service that does not correctly process the `HTTP PUT` request and leads to an `authenticated directory`/`path traversal,` and `arbitrary file write` vulnerability. This vulnerability allows us to write files outside the directory to which the service has access.

***

#### <mark style="color:green;">The Concept of the Attack</mark>

This FTP service uses an HTTP `POST` request to upload files. However, the CoreFTP service allows an HTTP `PUT` request, which we can use to write content to files. Let's have a look at the attack based on our concept. The [exploit](https://www.exploit-db.com/exploits/50652) for this attack is relatively straightforward, based on a single `cURL` command.

#### <mark style="color:green;">**CoreFTP Exploitation**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```
{% endcode %}

We create a raw HTTP `PUT` request (`-X PUT`) with basic auth (`--basic -u <username>:<password>`), the path for the file (`--path-as-is https://<IP>/../../../../../whoops`), and its content (`--data-binary "PoC."`) with this command. Additionally, we specify the host header (`-H "Host: <IP>"`) with the IP address of our target system.

#### <mark style="color:green;">**The Concept of Attacks**</mark>

![](https://academy.hackthebox.com/storage/modules/116/attack_concept2.png)

#### <mark style="color:green;">**Directory Traversal**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Step</strong></td><td><strong>Directory Traversal</strong></td><td><strong>Concept of Attacks - Category</strong></td></tr><tr><td><code>1.</code></td><td>The user specifies the type of HTTP request with the file's content, including escaping characters to break out of the restricted area.</td><td><code>Source</code></td></tr><tr><td><code>2.</code></td><td>The changed type of HTTP request, file contents, and path entered by the user are taken over and processed by the process.</td><td><code>Process</code></td></tr><tr><td><code>3.</code></td><td>The application checks whether the user is authorized to be in the specified path. Since the restrictions only apply to a specific folder, all permissions granted to it are bypassed as it breaks out of that folder using the directory traversal.</td><td><code>Privileges</code></td></tr><tr><td><code>4.</code></td><td>The destination is another process that has the task of writing the specified contents of the user on the local system.</td><td><code>Destination</code></td></tr></tbody></table>

Up to this point, we have bypassed the constraints imposed by the application using the escape characters (`../../../../`) and come to the second part, where the process writes the contents we specify to a file of our choice. This is when the cycle starts all over again, but this time to write contents to the target system.

#### <mark style="color:green;">**Arbitrary File Write**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Step</strong></td><td><strong>Arbitrary File Write</strong></td><td><strong>Concept of Attacks - Category</strong></td></tr><tr><td><code>5.</code></td><td>The same information that the user entered is used as the source. In this case, the filename (<code>whoops</code>) and the contents (<code>--data-binary "PoC."</code>).</td><td><code>Source</code></td></tr><tr><td><code>6.</code></td><td>The process takes the specified information and proceeds to write the desired content to the specified file.</td><td><code>Process</code></td></tr><tr><td><code>7.</code></td><td>Since all restrictions were bypassed during the directory traversal vulnerability, the service approves writing the contents to the specified file.</td><td><code>Privileges</code></td></tr><tr><td><code>8.</code></td><td>The filename specified by the user (<code>whoops</code>) with the desired content (<code>"PoC."</code>) now serves as the destination on the local system.</td><td><code>Destination</code></td></tr></tbody></table>

After the task has been completed, we will be able to find this file with the corresponding contents on the target system.

**Target System**

```cmd-session
C:\> type C:\whoops

PoC.
```
