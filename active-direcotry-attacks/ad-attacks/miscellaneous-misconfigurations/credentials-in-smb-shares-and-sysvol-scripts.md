# Credentials in SMB Shares and SYSVOL Scripts

### <mark style="color:blue;">Credentials in SMB Shares and SYSVOL Scripts</mark>

* **Qu’est-ce que SYSVOL ?**
  * C’est un partage accessible à **tous les utilisateurs authentifiés** d’un domaine Active Directory.
  * On y trouve notamment un dossier `scripts`.
* **Pourquoi c’est intéressant ?**
  * Ce répertoire contient souvent des **scripts Batch, VBScript, PowerShell** utilisés par les admins.
  * Ces scripts sont exécutés automatiquement pour gérer des postes ou déployer des configurations.
* **Ce qu’on peut y trouver** :
  * Des **mots de passe en clair** dans les scripts (ex. : `reset_local_admin_pass.vbs`).
  * Des comptes ou mots de passe anciens (parfois obsolètes), mais qui peuvent encore marcher.
* **Bonne pratique d’attaquant** :
  * Toujours explorer `SYSVOL\scripts`.
  * Même si 90 % du temps on tombe sur du vieux contenu, il arrive de trouver des **identifiants encore valides** = jackpot 💎.

<mark style="color:green;">**Discovering an Interesting Script**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts

    Directory: \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts


Mode                LastWriteTime         Length Name                                                                 
----                -------------         ------ ----                                                                 
-a----       11/18/2021  10:44 AM            174 daily-runs.zip                                                       
-a----        2/28/2022   9:11 PM            203 disable-nbtns.ps1                                                    
-a----         3/7/2022   9:41 AM         144138 Logon Banner.htm                                                     
-a----         3/8/2022   2:56 PM            979 reset_local_admin_pass.vbs  
```
{% endcode %}

Taking a closer look at the script, we see that it contains a password for the built-in local administrator on Windows hosts. In this case, it would be worth checking to see if this password is still set on any hosts in the domain. We could do this using CrackMapExec and the `--local-auth` flag as shown in this module's `Internal Password Spraying - from Linux` section.

<mark style="color:green;">**Finding a Password in the Script**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs

On Error Resume Next
strComputer = "."
 
Set oShell = CreateObject("WScript.Shell") 
sUser = "Administrator"
sPwd = "!ILFREIGHT_L0cALADmin!"
 
Set Arg = WScript.Arguments
If  Arg.Count > 0 Then
sPwd = Arg(0) 'Pass the password as parameter to the script
End if
 
'Get the administrator name
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")

<SNIP>
```
{% endcode %}
