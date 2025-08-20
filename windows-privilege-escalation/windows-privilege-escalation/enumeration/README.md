# Enumeration

***

### <mark style="color:red;">Network Information</mark>

<mark style="color:green;">**Interface(s), IP Address(es), DNS Information**</mark>

{% code fullWidth="true" %}
```powershell
C:\htb> ipconfig /all
```
{% endcode %}

<mark style="color:green;">**ARP Table**</mark>

{% code fullWidth="true" %}
```powershell
C:\htb> arp -a
```
{% endcode %}

<mark style="color:green;">**Routing Table**</mark>

{% code fullWidth="true" %}
```powershell
C:\htb> route print
```
{% endcode %}

***

### <mark style="color:red;">Enumerating Protections</mark>

<mark style="color:green;">**Check Windows Defender Status**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-MpComputerStatus
```
{% endcode %}

<mark style="color:green;">**List AppLocker Rules**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

```
{% endcode %}

<mark style="color:green;">**Test AppLocker Policy**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```
{% endcode %}
