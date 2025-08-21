# SSH for Windows: plink.exe

***

Plink, ou PuTTY Link, est un outil SSH en ligne de commande pour Windows, souvent utilisé pour créer des redirections de port et des proxys SOCKS. Avant 2018, Windows n’avait pas de client SSH natif, donc PuTTY était largement utilisé par les administrateurs. En pentest, si l’on obtient un accès à une machine Windows verrouillée, on peut utiliser Plink comme pivot pour rediriger le trafic sans transférer d’outils externes, en exploitant les programmes déjà présents sur le système. Il est aussi pratique si l’attaquant utilise Windows comme machine principale.

***

### <mark style="color:red;">Getting To Know Plink</mark>

![](https://academy.hackthebox.com/storage/modules/158/66.png)

<mark style="color:green;">**Using Plink.exe**</mark>

```cmd-session
plink -ssh -D 9050 ubuntu@10.129.15.50
```

***

Another <mark style="color:orange;">**Windows-based tool called**</mark> [<mark style="color:orange;">**Proxifier**</mark>](https://www.proxifier.com/) <mark style="color:orange;">**can be used to start a SOCKS tunnel via the SSH**</mark> session we created. Proxifier is a Windows tool that creates a tunneled network for desktop client applications and allows it to operate through a SOCKS or HTTPS proxy and allows for proxy chaining. It is possible to create a profile where we can provide the configuration for our SOCKS server started by Plink on port 9050.

![](https://academy.hackthebox.com/storage/modules/158/reverse_shell_9.png)

After configuring the SOCKS server for `127.0.0.1` and port 9050, we can directly start `mstsc.exe` to start an RDP session with a Windows target that allows RDP connections.
