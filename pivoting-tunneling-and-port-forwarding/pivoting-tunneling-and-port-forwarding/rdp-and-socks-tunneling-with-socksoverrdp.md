# RDP and SOCKS Tunneling with SocksOverRDP

***

Il y a souvent des moments **pendant une évaluation** où nous pouvons être **limités à un réseau Windows** et où nous ne pouvons pas utiliser **SSH pour le pivotement**.

Nous devrons utiliser **des outils disponibles pour les systèmes d’exploitation Windows** dans ces cas-là.

**SocksOverRDP** est un exemple d’outil qui utilise **Dynamic Virtual Channels (DVC)** de la **fonctionnalité Remote Desktop Service de Windows**.

**DVC est responsable du tunneling des paquets à travers la connexion RDP.**

Quelques exemples d’utilisation de cette fonctionnalité seraient :

* **Le transfert de données du presse-papiers**
* **Le partage audio**

Cependant, **cette fonctionnalité peut aussi être utilisée pour tunneler des paquets arbitraires sur le réseau.**

Nous pouvons utiliser **SocksOverRDP** pour **tunneler nos propres paquets** et ensuite **les proxyfier à travers lui**.

Nous allons utiliser **l’outil Proxifier comme serveur proxy.**

***

#### 📥 **Téléchargement des fichiers nécessaires**

Nous pouvons commencer par **télécharger les binaires appropriés** sur **notre machine d’attaque** pour exécuter cette attaque.

Avoir les binaires sur notre **machine d’attaque** nous permettra de **les transférer vers chaque cible où ils sont nécessaires**.

Nous aurons besoin de :\
✅ **Les binaires SocksOverRDP x64**\
✅ **Le binaire portable de Proxifier**\
✅ **Nous pouvons chercher le fichier** `ProxifierPE.zip`

***

#### 🔗 **Exécution sur la cible**

1️⃣ **Se connecter à la cible en utilisant xfreerdp**\
2️⃣ **Copier le fichier SocksOverRDPx64.zip sur la cible**\
3️⃣ **Depuis la machine Windows cible, charger la DLL** `SocksOverRDP.dll` en utilisant la commande suivante :

```powershell
regsvr32.exe SocksOverRDP.dll
```

<mark style="color:green;">**Loading SocksOverRDP.dll using regsvr32.exe**</mark>

```cmd-session
C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

![](https://academy.hackthebox.com/storage/modules/158/socksoverrdpdll.png)

Now we can connect to 172.16.5.19 over RDP using `mstsc.exe`, and we should receive a prompt that the SocksOverRDP plugin is enabled, and it will listen on 127.0.0.1:1080. We can use the credentials `victor:pass@123` to connect to 172.16.5.19.

![](https://academy.hackthebox.com/storage/modules/158/pivotingtoDC.png)

We will need to transfer SocksOverRDPx64.zip or just the SocksOverRDP-Server.exe to 172.16.5.19. We can then start SocksOverRDP-Server.exe with Admin privileges.

![](https://academy.hackthebox.com/storage/modules/158/executingsocksoverrdpserver.png)

When we go back to our foothold target and check with Netstat, we should see our SOCKS listener started on 127.0.0.1:1080.

**Confirming the SOCKS Listener is Started**

```cmd-session
C:\Users\htb-student\Desktop\SocksOverRDP-x64> netstat -antb | findstr 1080

  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING
```

After starting our listener, we can transfer Proxifier portable to the Windows 10 target (on the 10.129.x.x network), and configure it to forward all our packets to 127.0.0.1:1080. Proxifier will route traffic through the given host and port. See the clip below for a quick walkthrough of configuring Proxifier.

**Configuring Proxifier**

![](https://academy.hackthebox.com/storage/modules/158/configuringproxifier.gif)

With Proxifier configured and running, we can start mstsc.exe, and it will use Proxifier to pivot all our traffic via 127.0.0.1:1080, which will tunnel it over RDP to 172.16.5.19, which will then route it to 172.16.6.155 using SocksOverRDP-server.exe.

![](https://academy.hackthebox.com/storage/modules/158/rdpsockspivot.png)

**RDP Performance Considerations**

When interacting with our RDP sessions on an engagement, we may find ourselves contending with slow performance in a given session, especially if we are managing multiple RDP sessions simultaneously. If this is the case, we can access the `Experience` tab in mstsc.exe and set `Performance` to `Modem`.

![](https://academy.hackthebox.com/storage/modules/158/rdpexpen.png)

***
