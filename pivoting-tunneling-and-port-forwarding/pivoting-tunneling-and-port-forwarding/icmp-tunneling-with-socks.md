# ICMP Tunneling with SOCKS

***

{% hint style="warning" %}
L’**ICMP tunneling** encapsule votre trafic dans des **paquets ICMP** contenant des **requêtes et des réponses d’écho**.

L’ICMP tunneling fonctionne **uniquement** lorsque les **réponses aux pings sont autorisées** dans un réseau protégé par un pare-feu.

Lorsqu’un **hôte à l’intérieur d’un réseau** protégé par un pare-feu **est autorisé à pinguer** un serveur externe, il peut **encapsuler son trafic dans la requête de ping** et l’envoyer à un serveur externe.

Le serveur externe peut **valider ce trafic et envoyer une réponse appropriée**, ce qui est extrêmement utile pour **exfiltrer des données** et **créer des tunnels de pivotement** vers un serveur externe.

Nous allons utiliser l’outil **ptunnel-ng** pour **créer un tunnel entre notre serveur Ubuntu et notre machine d’attaque**.

Une fois le tunnel créé, nous pourrons **proxifier notre trafic à travers le client ptunnel-ng**.

Nous allons commencer par démarrer le **serveur ptunnel-ng** sur l’**hôte pivot** cible.

Commençons par installer et configurer **ptunnel-ng**
{% endhint %}

***

### <mark style="color:red;">Setting Up & Using ptunnel-ng</mark>

If ptunnel-ng is not on our attack host, we can clone the project using git.

<mark style="color:green;">**Cloning Ptunnel-ng**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ git clone https://github.com/utoni/ptunnel-ng.git
```

Once the ptunnel-ng repo is cloned to our attack host, we can run the `autogen.sh` script located at the root of the ptunnel-ng directory.

<mark style="color:green;">**Building Ptunnel-ng with Autogen.sh**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo ./autogen.sh 
```

<mark style="color:green;">**Alternative approach of building a static binary**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo apt install automake autoconf -y
mrroboteLiot@htb[/htb]$ cd ptunnel-ng/
mrroboteLiot@htb[/htb]$ sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
mrroboteLiot@htb[/htb]$ ./autogen.sh
```

<mark style="color:green;">**Transferring Ptunnel-ng to the Pivot Host**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

With ptunnel-ng on the target host, we can start the server-side of the ICMP tunnel using the command directly below.

<mark style="color:green;">**Starting the ptunnel-ng Server on the Target Host**</mark>

```shell-session
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22
```

The IP address following `-r` should be the IP we want ptunnel-ng to accept connections on. In this case, whatever IP is reachable from our attack host would be what we would use. We would benefit from using this same thinking & consideration during an actual engagement.

Back on the attack host, we can attempt to connect to the ptunnel-ng server (`-p <ipAddressofTarget>`) but ensure this happens through local port 2222 (`-l2222`). Connecting through local port 2222 allows us to send traffic through the ICMP tunnel.

<mark style="color:green;">**Connecting to ptunnel-ng Server from Attack Host**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

With the ptunnel-ng ICMP tunnel successfully established, we can attempt to connect to the target using SSH through local port 2222 (`-p2222`).

<mark style="color:green;">**Tunneling an SSH connection through an ICMP Tunnel**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ ssh -p2222 -lubuntu 127.0.0.1
```

If configured correctly, we will be able to enter credentials and have an SSH session all through the ICMP tunnel.

On the client & server side of the connection, we will notice ptunnel-ng gives us session logs and traffic statistics associated with the traffic that passes through the ICMP tunnel. This is one way we can confirm that our traffic is passing from client to server utilizing ICMP.

<mark style="color:green;">**Viewing Tunnel Traffic Statistics**</mark>

```shell-session
inf]: Incoming tunnel request from 10.10.14.18.
[inf]: Starting new session to 10.129.202.64:22 with ID 20199
[inf]: Received session close from remote peer.
[inf]: 
Session statistics:
[inf]: I/O:   0.00/  0.00 mb ICMP I/O/R:      248/      22/       0 Loss:  0.0%
[inf]: 
```

We may also use this tunnel and SSH to perform dynamic port forwarding to allow us to use proxychains in various ways.

<mark style="color:green;">**Enabling Dynamic Port Forwarding over SSH**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

We could use proxychains with Nmap to scan targets on the internal network (172.16.5.x). Based on our discoveries, we can attempt to connect to the target.

<mark style="color:green;">**Proxychaining through the ICMP Tunnel**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ proxychains nmap -sV -sT 172.16.5.19 -p3389
```
{% endcode %}

***

### <mark style="color:red;">Network Traffic Analysis Considerations</mark>

It is important that we confirm the tools we are using are performing as advertised and that we have set up & are operating them properly. In the case of tunneling traffic through different protocols taught in this section with ICMP tunneling, we can benefit from analyzing the traffic we generate with a packet analyzer like `Wireshark`. Take a close look at the short clip below.

![](https://academy.hackthebox.com/storage/modules/158/analyzingTheTraffic.gif)

In the first part of this clip, a connection is established over SSH without using ICMP tunneling. We may notice that `TCP` & `SSHv2` traffic is captured.

The command used in the clip: `ssh ubuntu@10.129.202.64`

In the second part of this clip, a connection is established over SSH using ICMP tunneling. Notice the type of traffic that is captured when this is performed.

Command used in clip: `ssh -p2222 -lubuntu 127.0.0.1`

***
