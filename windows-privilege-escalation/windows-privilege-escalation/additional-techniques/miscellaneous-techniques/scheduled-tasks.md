# Scheduled Tasks

### <mark style="color:red;">Scheduled Tasks</mark>

<mark style="color:green;">**Enumerating Scheduled Tasks**</mark>

&#x20;[schtasks](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)

{% code fullWidth="true" %}
```cmd-session
schtasks /query /fo LIST /v
```
{% endcode %}

<mark style="color:green;">**Enumerating Scheduled Tasks with PowerShell**</mark>

[Get-ScheduledTask](https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask?view=windowsserver2019-ps)

```powershell-session
Get-ScheduledTask | select TaskName,State
```

{% hint style="info" %}
Par défaut, un utilisateur standard ne voit que **ses propres tâches** et les tâches système.

* Les tâches créées par d’autres utilisateurs (admins) sont dans `C:\Windows\System32\Tasks` et **sont normalement inaccessibles**.
* Parfois, des admins donnent par erreur des **permissions trop larges**.
* Dans ce cas, on peut **modifier la tâche ou son script** pour exécuter quelque chose à notre avantage.
{% endhint %}

<mark style="color:green;">**Checking Permissions on C:\Scripts Directory**</mark>

```cmd-session
C:\htb> .\accesschk64.exe /accepteula -s -d C:\Scripts\
 
```

* Des scripts de sauvegarde sont **modifiables par tous les utilisateurs**.
* On peut **ajouter du code malveillant** qui sera exécuté automatiquement.
* Quand le script s’exécute, il peut **lancer un accès SYSTEM** vers notre infrastructure.
* Même de **petites infos découvertes** peuvent être cruciales pour réussir l’attaque.
