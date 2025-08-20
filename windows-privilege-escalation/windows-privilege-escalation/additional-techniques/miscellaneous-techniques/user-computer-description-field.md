# User/Computer Description Field

### <mark style="color:red;">User/Computer Description Field</mark>

<mark style="color:green;">**Checking Local User Description Field**</mark>

```powershell-session
PS C:\htb> Get-LocalUser
```

<mark style="color:green;">**Enumerating Computer Description Field with Get-WmiObject Cmdlet**</mark>

```powershell-session
PS C:\htb> Get-WmiObject -Class Win32_OperatingSystem | select Description
```
