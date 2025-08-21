# Port Forwarding with Windows Netsh

***

Netsh est un outil en ligne de commande de Windows permettant de gérer la configuration réseau d’un système. Il permet notamment de :

* Consulter les routes
* Voir la configuration du pare-feu
* Ajouter des proxies
* Créer des règles de redirection de ports

Par exemple, sur une machine compromise d’un administrateur Windows 10 (10.129.15.150, 172.16.5.25), on peut utiliser `netsh.exe` pour rediriger toutes les données reçues sur un port spécifique (par exemple 8080) vers un hôte distant sur un autre port, facilitant ainsi le pivot dans le réseau.

![](https://academy.hackthebox.com/storage/modules/158/88.png)

<mark style="color:green;">**Using Netsh.exe to Port Forward**</mark>

{% code overflow="wrap" fullWidth="true" %}
```cmd-session
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25
```
{% endcode %}

<mark style="color:green;">**Verifying Port Forward**</mark>

```cmd-session
C:\Windows\system32> netsh.exe interface portproxy show v4tov4

10.129.42.198   8080        172.16.5.25     3389
```

After configuring the `portproxy` on our Windows-based pivot host, we will try to connect to the 8080 port of this host from our attack host using xfreerdp. Once a request is sent from our attack host, the Windows host will route our traffic according to the proxy settings configured by netsh.exe.

<mark style="color:green;">**Connecting to the Internal Host through the Port Forward**</mark>

![](https://academy.hackthebox.com/storage/modules/158/netsh_pivot.png)

***
