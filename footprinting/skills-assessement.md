# SKILLS ASSESSEMENT

## <mark style="color:red;">**Lab Easy**</mark> <a href="#id-16be" id="id-16be"></a>

Some key points

* company is InlaneFreight Ltd
* inernal DNS server
* gather as much info as possible about the server and find ways to use info against company
* **Forbidden** to attack services aggressively using exploits (Important)
* credentials “ceil:qwer1234” (can be used to log in)
* SSH keys on a forum (hmmmm)
* stored a flag.txt file (this is our goal to get to this flag)

Firstly, I did

```
nmap -sC -sV <ip>
```

I found port 21/tcp(ftp), port 22/tcp(ssh), port 53/tcp(I think zone transfer generally happens over TCP port 53), port 2121/tcp(ftp)

I kinda went down the path of dig, dig axfr which I don’t think is the way

I saw port 21, so I thought ok why not try ftp into it, since they gave me the username and password as well

```
ftp <ip>

entered my username and password

tried ls cannot find anything, thought nothing much so hit a dead end
```

after reading the forum and the hints….

```
ftp <ip>
entered username and password 
ls -shila

found . and .. 
cd into them and ls -shila cannot find anything

exited using bye command
ftp ceil@<ip> 2121 (they gave another port)
entered password
ls -shila
found .ssh
cd .ssh
ls (found authorized_keys, id_rsa, id_rsa.pub)

decided to get everything

mget authorized_keys od_rsa id_rsa.pub
```

* now I have 3 files in my directory
* tried…

```
ssh -v ceil@<ip>

saw a bunch of output and permission denied hmmmm

saw at the end a bunch of Trying private key: /home/htb-ac-[number]/.ssh/[sth]

hmmmmm maybe put the files inside there

so I moved the files into .ssh folder
```

hmmmm after this permission is still denied…saw the hint and forum as well as online websites again…

[How To Fix SSH Permission Denied (Publickey) ErrorThis tutorial teaches how to troubleshoot and fix the SSH Permission Denied (Publickey) error. Fix common SSH…www.redswitches.com](https://www.redswitches.com/blog/ssh-permission-denied/?source=post_page-----95c46a6a66e4--------------------------------)

* saw chmod 600 and decided to just anyhow try

```
chmod 600 authorized_keys id_rsa id_rsa.pub

after that ssh -v ceil@<ip> AND I AM IN

went to ls saw nothing again what the

ls -shila 

decided to cd ../

ls -shila

found flag 
cd into it and found the flag.txt
```

***

## <mark style="color:red;">Lab Medium</mark>

#### 1. **Reconnaissance et Scanning avec Nmap**

*   Exécution de **Nmap** pour l'énumération des services sur la machine cible (IP: `10.129.202.41`) :

    ```bash
    sudo nmap -F -sC -sV -A -oX nmap.xml 10.129.202.41
    ```
*   Analyse des résultats avec **xsltproc** et visualisation dans le navigateur :

    ```bash
    xsltproc nmap.xml -o nmap.html
    firefox nmap.html
    ```

**Ports importants découverts :**

* 111 (RPCBind)
* 139 (NetBIOS-SSN)
* 445 (Microsoft-DS, SMB)
* 2049 (NFS)
* 3389 (RDP)

#### 2. **Énumération des services RPC avec rpcinfo**

*   Utilisation de **rpcinfo** pour lister les services RPC :

    ```bash
    rpcinfo -p 10.129.202.41
    ```

#### 3. **Montage des partages NFS**

*   Vérification des partages NFS disponibles avec **showmount** et montage du partage :

    ```bash
    sudo mount -t nfs 10.129.202.41:/TechSupport ./targetNFS -o nolock
    sudo ls ./targetNFS
    ```
* Un fichier contenant des identifiants en **texte clair** a été trouvé :
  * **Nom d'utilisateur** : alex
  * **Mot de passe** : lol123!mD

#### 4. **Énumération et Accès SMB**

*   Connexion au service SMB avec **smbclient** et énumération des partages disponibles :

    ```bash
    smbclient -U 'alex' -L //10.129.202.41/
    ```
*   Accès au partage `devshare` et récupération d'un fichier :

    ```bash
    smbclient -U 'alex' //10.129.202.41/devshare
    get important.txt
    cat important.txt
    ```
* **Mot de passe récupéré** dans `important.txt` :
  * **sa:87N1ns@slls83**

#### 5. **Connexion RDP avec xfreerdp**

*   Connexion au serveur RDP avec les identifiants trouvés :

    ```bash
    xfreerdp /u:alex /p:'lol123!mD' /v:10.129.202.41
    ```

#### 6. **Exploration de MSSQL**

* Une fois connecté via RDP, l'utilisateur accède à **Microsoft SQL Server** en tant qu'administrateur pour éviter les restrictions de permissions.
* Les identifiants MSSQL sont récupérés dans `important.txt`.
* L'utilisateur parcourt les bases de données et accède à la table `dbo.devsacc` pour trouver l'utilisateur **HTB**.

#### **Résultat Final :**

*   La clé/flag trouvé :

    ```bash
    flag: lnch7ehrdn43i7AoqVPK4zWR
    ```

Ce processus a permis de faire une **énumération réseau**, de récupérer des **identifiants sensibles**, d'accéder à une machine via **SMB et RDP**, et finalement d'extraire des informations critiques à partir d'une **base de données MSSQL**.

Cette approche méthodique a permis une couverture complète des points d'accès et la découverte de données clés.

***

## <mark style="color:red;">Lab - Hard</mark>

Initially, we'll conduct reconnaissance to detect open ports. This involves performing TCP and UDP port scans to identify all available open ports.

<figure><img src="../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

TCP Port Scan

<figure><img src="../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

UDP Port Scan

Here are the open ports detected following a scan of TCP and UDP ports.

I attempted to experiment with the IMAP and POP3 services, but unfortunately encountered no success. Let's now investigate the UDP services to determine potential findings. UDP Port 161 is accessible, indicating the presence of an SNMP service.

**SNMP - Simple Network Management Protocol** is a protocol used to monitor different devices in the network (like routers, switches, printers, IoTs...).

For footprinting SNMP, we can use tools like `snmpwalk`, `onesixtyone`, and `braa`. `Snmpwalk` is used to query the OIDs with their information. `Onesixtyone` can be used to brute-force the names of the community strings since they can be named arbitrarily by the administrator. Since these community strings can be bound to any source, identifying the existing community strings can take quite some time.

I attempted to utilize snmpwalk, but encountered no response.

<figure><img src="../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

Now I don't know the community string, so I used **`onesixtyone`**&#x74;ool and **`Seclists`**&#x77;ordlists to identify these community strings.

In order to access the information saved on the **MIB** you need to know the community string on versions 1 and 2/2c and the credentials on version 3.

The are 2 types of community strings:

* **`public`** mainly **read only** functions
* **`private`** **Read/Write** in general

<figure><img src="../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

I discovered a community string, which is enclosed within the brackets \[]. Let's utilize this community string with the braa tool to explore the available information.

<figure><img src="../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

After employing Braa with the discovered community string, I obtained credentials for a user named 'Tom'. Let's attempt to utilize these credentials with IMAP to ascertain the available data.

<figure><img src="https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FM3nqvIZvM6D53IhFdtwQ%252FScreenshot%285%29.png%3Falt%3Dmedia%26token%3Dec55c572-1a0f-49dc-9ae9-cddfa7a36b48&#x26;width=768&#x26;dpr=4&#x26;quality=100&#x26;sign=f6df939b&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Here's what I've accomplished:

1. Logged in with the comman&#x64;**`LOGIN username password`**
2. Listed all directories usin&#x67;**`LIST "" *`**
3. Selected the 'INBOX' mailbox with **`SELECT "INBOX"`**
4. Checked for available messages with **`1 STATUS INBOX (MESSAGES)`** and found one
5. Retrieved the entire message with **`1 FETCH 1 all`**
6. Obtained the message content using **`1 FETCH 1 BODY[]`**

<figure><img src="https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252F2EawNKkgIMAfrutoD5XX%252FScreenshot%287%29.png%3Falt%3Dmedia%26token%3Df1dfd5c1-83e3-496e-aff3-19e411a09e99&#x26;width=768&#x26;dpr=4&#x26;quality=100&#x26;sign=c194ac30&#x26;sv=2" alt=""><figcaption></figcaption></figure>

I discovered a private key associated with the user 'Tom' in the message. Let's attempt to SSH using this key.

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

I saved the private key as `id_rsa` and adjusted its permissions before using SSH to gain access to the target.

After conducting enumeration, I compiled a list of all files within the current directory belonging to the user 'tom.' Subsequently, I examined the`.bash_history` file and discovered the presence of a MySQL command within it.

<figure><img src="../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Let's attempt to access MySQL by entering the command **`mysql -u tom -p`**, utilizing the previously discovered password for the user 'Tom'.

<figure><img src="https://faresbltagy.gitbook.io/~gitbook/image?url=https%3A%2F%2F2537271824-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FIswWWP3l0rGuQmG2WUcr%252Fuploads%252FHDtf45m5CNBQBTHn92Wj%252FScreenshot%2811%29.png%3Falt%3Dmedia%26token%3Dc04be76f-ede2-4288-99c7-728a75c432e8&#x26;width=768&#x26;dpr=4&#x26;quality=100&#x26;sign=2fb3a031&#x26;sv=2" alt=""><figcaption></figcaption></figure>

Upon logging in, I discovered a database named **`users`**&#x63;ontaining a table labeled as such. I proceeded to extract a comprehensive list of all columns within the **`users`** table, ultimately obtaining the password associated with the **`HTB`** user.
