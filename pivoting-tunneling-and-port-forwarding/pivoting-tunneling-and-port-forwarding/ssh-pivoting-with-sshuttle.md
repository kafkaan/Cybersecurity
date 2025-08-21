# SSH Pivoting with Sshuttle

***

Sshuttle est un outil Python qui simplifie le pivoting SSH sans avoir besoin de configurer proxychains. Il ne fonctionne que sur SSH et ne gère pas TOR ou les proxies HTTPS, mais il automatise facilement l’ajout de règles de pivot sur l’hôte distant. On peut l’utiliser pour router tout le trafic réseau, par exemple celui de Nmap, via un serveur Ubuntu configuré comme pivot. Il permet aussi de se connecter aux hôtes distants, comme un Windows via RDP, sans passer par proxychains.

<mark style="color:green;">**Installing sshuttle**</mark>

```shell-session
sudo apt-get install sshuttl
```

<mark style="color:green;">**Running sshuttle**</mark>

{% code fullWidth="true" %}
```shell-session
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```
{% endcode %}

<mark style="color:green;">**Traffic Routing through iptables Routes**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ nmap -v -sV -p3389 172.16.5.19 -A -Pn

```
