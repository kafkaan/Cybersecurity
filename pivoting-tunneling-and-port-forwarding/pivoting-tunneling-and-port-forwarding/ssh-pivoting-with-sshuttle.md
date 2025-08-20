# SSH Pivoting with Sshuttle

***

[Sshuttle](https://github.com/sshuttle/sshuttle) is another tool written in Python which removes the need to configure proxychains. However, this tool only works for pivoting over SSH and does not provide other options for pivoting over TOR or HTTPS proxy servers. `Sshuttle` can be extremely useful for automating the execution of iptables and adding pivot rules for the remote host. We can configure the Ubuntu server as a pivot point and route all of Nmap's network traffic with sshuttle using the example later in this section.

One interesting usage of sshuttle is that we don't need to use proxychains to connect to the remote hosts. Let's install sshuttle via our Ubuntu pivot host and configure it to connect to the Windows host via RDP.

<mark style="color:green;">**Installing sshuttle**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo apt-get install sshuttl
```

To use sshuttle, we specify the option `-r` to connect to the remote machine with a username and password. Then we need to include the network or IP we want to route through the pivot host, in our case, is the network 172.16.5.0/23.

<mark style="color:green;">**Running sshuttle**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```
{% endcode %}

With this command, sshuttle creates an entry in our `iptables` to redirect all traffic to the 172.16.5.0/23 network through the pivot host.

<mark style="color:green;">**Traffic Routing through iptables Routes**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ nmap -v -sV -p3389 172.16.5.19 -A -Pn

```

We can now use any tool directly without using proxychains.
