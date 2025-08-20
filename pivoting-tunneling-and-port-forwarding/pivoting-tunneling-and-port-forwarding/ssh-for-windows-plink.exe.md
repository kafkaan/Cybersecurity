# SSH for Windows: plink.exe

***

Plink, abréviation de **PuTTY Link**, est un outil SSH en ligne de commande pour Windows, inclus dans le package PuTTY lors de son installation. Tout comme SSH, Plink peut être utilisé pour créer des redirections de port dynamiques et des proxys SOCKS.

Avant l’automne 2018, Windows ne disposait pas de client SSH natif intégré, ce qui obligeait les utilisateurs à installer leur propre solution. L’outil privilégié par de nombreux administrateurs système pour se connecter à d’autres machines était **PuTTY**.

Imaginons que nous soyons en train de réaliser un pentest et que nous obtenions un accès à une machine Windows. Nous effectuons rapidement une reconnaissance du système et de sa posture de sécurité et constatons qu’il est modérément verrouillé. Nous devons utiliser cet hôte comme point de pivot, mais il est peu probable que nous puissions y transférer nos propres outils sans être détectés.

À la place, nous pouvons utiliser les outils déjà présents sur le système (**"Living off the Land"**). Si la machine est ancienne et que **PuTTY** est installé (ou si nous pouvons en trouver une copie sur un partage de fichiers), **Plink peut être notre clé du succès**. Nous pouvons l’utiliser pour établir notre pivot et **éventuellement éviter la détection un peu plus longtemps**.

Ce n’est qu’un des nombreux scénarios où **Plink** peut être utile. Nous pourrions également l’utiliser si notre machine d’attaque principale est sous **Windows**, plutôt qu’un système basé sur **Linux**.

***

### <mark style="color:red;">Getting To Know Plink</mark>

![](https://academy.hackthebox.com/storage/modules/158/66.png)

The Windows attack host starts a plink.exe process with the below command-line arguments to start a dynamic port forward over the Ubuntu server. This starts an SSH session between the Windows attack host and the Ubuntu server, and then plink starts listening on port 9050.

**Using Plink.exe**

```cmd-session
plink -ssh -D 9050 ubuntu@10.129.15.50
```

Another <mark style="color:orange;">**Windows-based tool called**</mark> [<mark style="color:orange;">**Proxifier**</mark>](https://www.proxifier.com/) <mark style="color:orange;">**can be used to start a SOCKS tunnel via the SSH**</mark> session we created. Proxifier is a Windows tool that creates a tunneled network for desktop client applications and allows it to operate through a SOCKS or HTTPS proxy and allows for proxy chaining. It is possible to create a profile where we can provide the configuration for our SOCKS server started by Plink on port 9050.

![](https://academy.hackthebox.com/storage/modules/158/reverse_shell_9.png)

After configuring the SOCKS server for `127.0.0.1` and port 9050, we can directly start `mstsc.exe` to start an RDP session with a Windows target that allows RDP connections.
