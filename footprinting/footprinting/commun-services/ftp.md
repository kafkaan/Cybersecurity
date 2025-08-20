---
description: >-
  Le protocole de transfert de fichiers (FTP) est l’un des plus anciens
  protocoles sur Internet. Le FTP fonctionne au sein de la couche application de
  la pile de protocoles TCP/IP. Il se situe donc au m
cover: ../../../.gitbook/assets/mainimage-1.jpg
coverY: 0
---

# FTP

> A distinction is made between <mark style="color:red;">**`active`**</mark> and <mark style="color:red;">**`passive`**</mark>
>
> **Dans la variante active, le client établit la connexion via le port TCP 21, et informe ainsi le serveur du port client par lequel ce dernier peut transmettre ses réponses. Cependant, si une pare-feu protège le client, le serveur ne peut pas répondre, car toutes les connexions entrantes sont bloquées.**
>
> **Pour résoudre ce problème, un mode passif a été développé. Dans ce mode, c’est le serveur qui annonce un port par lequel le client peut établir le canal de données.**
>
> **Comme c’est le client qui initie la connexion dans cette méthode, le pare-feu ne bloque pas le transfert.**

{% hint style="info" %}
<mark style="color:orange;">**Mode Actif :**</mark>

1. **Client établit la connexion de commande :** Le client envoie une demande de connexion au serveur FTP sur le port 21, qui est le port de commande standard du FTP.
2. **Serveur ouvre une connexion de données :** Une fois que le serveur reçoit la demande de connexion de la part du client, il ouvre une nouvelle connexion de données vers le client en utilisant un port aléatoire non réservé.
3. **Serveur envoie des données au client :** Le serveur envoie ensuite les données demandées sur cette nouvelle connexion de données vers le port spécifié par le client.

Dans ce mode, le client est responsable de spécifier le port sur lequel il souhaite recevoir les données. Cependant, cela peut poser problème si le client est derrière un pare-feu qui bloque les connexions entrantes, car le serveur ne peut pas établir une connexion de retour avec le client.

***

<mark style="color:orange;">**Mode Passif :**</mark>

1. **Client établit la connexion de commande :** Le client envoie une demande de connexion au serveur FTP sur le port 21, comme dans le mode actif.
2. **Serveur annonce un port de données :** Au lieu d'ouvrir une connexion de données vers le client, le serveur annonce un port sur lequel le client peut se connecter pour établir la connexion de données.
3. **Client établit la connexion de données :** Le client se connecte ensuite au port annoncé par le serveur pour établir la connexion de données.
4. **Serveur envoie des données au client :** Une fois que la connexion de données est établie, le serveur envoie les données demandées au client sur cette connexion. \</aside>
{% endhint %}

***

## <mark style="color:red;">TFTP</mark>

* **TFTP** est un <mark style="color:orange;">**protocole de transfert de fichiers plus simple que FTP**</mark>.
* **TFTP** ne fournit pas d’authentification utilisateur et d’autres fonctionnalités prises en charge par FTP.
* **TFTP** utilise UDP, ce qui en fait un protocole peu fiable.
* **TFTP** ne nécessite pas l’authentification de l’utilisateur et ne prend pas en charge la connexion protégée par des mots de passe.
* **TFTP** fonctionne exclusivement dans des répertoires et avec des fichiers partagés avec tous les utilisateurs et pouvant être lus et écrits globalement.
* **TFTP** ne peut être utilisé que dans des réseaux locaux et protégés.

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><code>connect</code></td><td>Sets the remote host, and optionally the port, for file transfers.</td></tr><tr><td><code>get</code></td><td>Transfers a file or set of files from the remote host to the local host.</td></tr><tr><td><code>put</code></td><td>Transfers a file or set of files from the local host onto the remote host.</td></tr><tr><td><code>quit</code></td><td>Exits tftp.</td></tr><tr><td><code>status</code></td><td>Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on.</td></tr><tr><td><code>verbose</code></td><td>Turns verbose mode, which displays additional information during file transfer, on or off.</td></tr></tbody></table>

***

## <mark style="color:red;">Default Configuration</mark>

&#x20;The default configuration of vsFTPd can be found in <mark style="color:red;">**`/etc/vsftpd.conf`**</mark>

```shell-session
sudo apt install vsftpd 
```

```shell-session
cat /etc/vsftpd.conf | grep -v "#"
```

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Setting</strong></td><td><strong>Description</strong></td></tr><tr><td><code>listen=NO</code></td><td>Run from inetd or as a standalone daemon?</td></tr><tr><td><code>listen_ipv6=YES</code></td><td>Listen on IPv6 ?</td></tr><tr><td><code>anonymous_enable=NO</code></td><td>Enable Anonymous access?</td></tr><tr><td><code>local_enable=YES</code></td><td>Allow local users to login?</td></tr><tr><td><code>dirmessage_enable=YES</code></td><td>Display active directory messages when users go into certain directories?</td></tr><tr><td><code>use_localtime=YES</code></td><td>Use local time?</td></tr><tr><td><code>xferlog_enable=YES</code></td><td>Activate logging of uploads/downloads?</td></tr><tr><td><code>connect_from_port_20=YES</code></td><td>Connect from port 20?</td></tr><tr><td><code>secure_chroot_dir=/var/run/vsftpd/empty</code></td><td>Name of an empty directory</td></tr><tr><td><code>pam_service_name=vsftpd</code></td><td>This string is the name of the PAM service vsftpd will use.</td></tr><tr><td><code>rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem</code></td><td>The last three options specify the location of the RSA certificate to use for SSL encrypted connections.</td></tr><tr><td><code>rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key</code></td><td></td></tr><tr><td><code>ssl_enable=NO</code></td><td></td></tr></tbody></table>

{% hint style="info" %}
there is a file called `/etc/ftpusers` that we also need to pay attention to, as this file is used to deny certain users access to the FTP service
{% endhint %}

***

## <mark style="color:red;">Dangerous Settings</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th width="434"></th><th></th></tr></thead><tbody><tr><td><strong>Setting</strong></td><td><strong>Description</strong></td></tr><tr><td><code>anonymous_enable=YES</code></td><td>Allowing anonymous login?</td></tr><tr><td><code>anon_upload_enable=YES</code></td><td>Allowing anonymous to upload files?</td></tr><tr><td><code>anon_mkdir_write_enable=YES</code></td><td>Allowing anonymous to create new directories?</td></tr><tr><td><code>no_anon_password=YES</code></td><td>Do not ask anonymous for password?</td></tr><tr><td><code>anon_root=/home/username/ftp</code></td><td>Directory for anonymous.</td></tr><tr><td><code>write_enable=YES</code></td><td>Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE?</td></tr></tbody></table>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Setting</strong></td><td><strong>Description</strong></td></tr><tr><td><code>dirmessage_enable=YES</code></td><td>Show a message when they first enter a new directory?</td></tr><tr><td><code>chown_uploads=YES</code></td><td>Change ownership of anonymously uploaded files?</td></tr><tr><td><code>chown_username=username</code></td><td>User who is given ownership of anonymously uploaded files.</td></tr><tr><td><code>local_enable=YES</code></td><td>Enable local users to login?</td></tr><tr><td><code>chroot_local_user=YES</code></td><td>Place local users into their home directory?</td></tr><tr><td><code>chroot_list_enable=YES</code></td><td>Use a list of local users that will be placed in their home directory?</td></tr></tbody></table>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Setting</strong></td><td><strong>Description</strong></td></tr><tr><td><code>hide_ids=YES</code></td><td>All user and group information in directory listings will be displayed as "ftp".</td></tr><tr><td><code>ls_recurse_enable=YES</code></td><td>Allows the use of recurse listings.</td></tr></tbody></table>

***

## <mark style="color:red;">**Download All Available Files**</mark>

```bash
 wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

***

## <mark style="color:red;">Footprinting the Service</mark>

***

### <mark style="color:blue;">**Nmap FTP Scripts**</mark>

```shell-session
sudo nmap --script-updatedb
```

All the NSE scripts are located on the Pwnbox in `/usr/share/nmap/scripts/`

```shell-session
find / -type f -name ftp* 2>/dev/null | grep scripts
```

```shell-session
sudo nmap -sV -p21 -sC -A 10.129.14.136
```

```shell-session
sudo nmap -sV -p21 -sC -A 10.129.14.136 --script-trace
```

***

### <mark style="color:blue;">**Service Interaction**</mark>

<pre class="language-shell-session"><code class="lang-shell-session"><strong>nc -nv 10.129.14.136 21 //
</strong></code></pre>

```shell-session
telnet 10.129.14.136 21
```

```shell-session
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```
