# Communication with Processes

***

{% hint style="warning" %}
**L’analyse des processus en cours est clé pour l’escalade de privilèges** : un service web (IIS, XAMPP, etc.) peut offrir un accès avec l’utilisateur du service, qui dispose parfois du jeton **SeImpersonate**, exploitable avec des attaques type _Potato_ pour obtenir **SYSTEM**.
{% endhint %}

***

### <mark style="color:red;">Access Tokens</mark>

{% hint style="info" %}
Dans Windows, les jetons d'accès sont utilisés pour décrire le contexte de sécurité (attributs ou règles de sécurité) d'un processus ou d'un thread. Le jeton inclut des informations sur l'identité du compte utilisateur et les privilèges associés à un processus ou thread spécifique. Lorsqu'un utilisateur s'authentifie sur un système, son mot de passe est vérifié par rapport à une base de données de sécurité, et si l'authentification est réussie, un jeton d'accès lui est attribué. Chaque fois qu'un utilisateur interagit avec un processus, une copie de ce jeton est présentée pour déterminer son niveau de privilège
{% endhint %}

***

### <mark style="color:red;">Enumerating Network Services</mark>

<mark style="color:green;">**Display Active Network Connections**</mark>

```cmd-session
C:\htb> netstat -ano
```

***

### <mark style="color:red;">Named Pipes</mark>

[https://csandker.io/2021/01/10/Offensive-Windows-IPC-1-NamedPipes.html](https://csandker.io/2021/01/10/Offensive-Windows-IPC-1-NamedPipes.html)

{% hint style="info" %}
Une autre manière pour les processus de communiquer entre eux est l’utilisation de **tuyaux nommés**. Les tuyaux sont essentiellement des fichiers stockés en mémoire qui sont effacés après avoir été lus. Cobalt Strike utilise des tuyaux nommés pour chaque commande (à l’exception de BOF). Essentiellement, le flux de travail se déroule ainsi :

1. **Beacon** démarre un tuyau nommé de type .\pipe\msagent\_12.
2. **Beacon** démarre un nouveau processus et injecte une commande dans ce processus, redirigeant la sortie vers .\pipe\msagent\_12.
3. Le serveur affiche ce qui a été écrit dans .\pipe\msagent\_12.

Cobalt Strike a adopté cette méthode car si la commande exécutée était détectée par un antivirus ou provoquait un crash, cela n’affecterait pas le **beacon** (le processus exécutant la commande). Souvent, les utilisateurs de Cobalt Strike changent les noms de leurs tuyaux nommés pour se faire passer pour un autre programme. Un exemple courant est d’utiliser "mojo" au lieu de "msagent". L’un de mes exemples préférés était la découverte d’un tuyau nommé "mojo", alors que l'ordinateur n’avait pas Chrome installé. Heureusement, il s’est avéré que c’était l’équipe interne de l’entreprise qui réalisait des tests de pénétration. Cela en dit long lorsqu'un consultant externe trouve l’équipe rouge, mais que l’équipe bleue interne ne l’a pas remarquée.
{% endhint %}

***

<mark style="color:green;">**Plus sur les tuyaux nommés**</mark>

{% hint style="info" %}
Les tuyaux sont utilisés pour la communication entre deux applications ou processus via une mémoire partagée. Il existe deux types de tuyaux :&#x20;

* les tuyaux nommés&#x20;
* les tuyaux anonymes.&#x20;

Un exemple de tuyau nommé est `\\.\PipeName\ExampleNamedPipeServer`. Les systèmes Windows utilisent une implémentation client-serveur pour la communication par tuyau. Dans ce type d’implémentation, le processus qui crée un tuyau nommé est le serveur, et le processus qui communique avec ce tuyau est le client.

Les tuyaux nommés peuvent communiquer de deux manières :

* **Demi-duplex** : un canal unidirectionnel où seul le client peut écrire des données vers le serveur.
* **Duplex** : un canal bidirectionnel qui permet au client d’écrire des données sur le tuyau et au serveur de répondre en renvoyant des données.

Chaque connexion active à un serveur de tuyau nommé entraîne la création d’un nouveau tuyau nommé. Tous ces tuyaux partagent le même nom, mais communiquent en utilisant des tampons de données différents.

Nous pouvons utiliser l'outil <mark style="color:orange;">**PipeList**</mark> de la <mark style="color:orange;">**Sysinternals**</mark>**&#x20;Suite** pour énumérer les instances de tuyaux nommés.
{% endhint %}

<mark style="color:green;">**Listing Named Pipes with Pipelist**</mark>

```cmd-session
C:\htb> pipelist.exe /accepteula
```

Additionally, we can use PowerShell to list named pipes using <mark style="color:orange;">**`gci`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**(**</mark><mark style="color:orange;">**`Get-ChildItem`**</mark><mark style="color:orange;">**)**</mark>.

<mark style="color:green;">**Listing Named Pipes with PowerShell**</mark>

```powershell-session
PS C:\htb>  gci \\.\pipe\
```

{% hint style="warning" %}
Après avoir obtenu la liste des _named pipes_ (canaux nommés), nous pouvons utiliser **Accesschk** pour énumérer les permissions attribuées à un _named pipe_ spécifique en examinant la **Discretionary Access Control List (DACL)**, qui indique qui a les droits de modifier, écrire, lire ou exécuter une ressource.

Prenons par exemple le processus **LSASS**.\
Nous pouvons également examiner les DACLs de **tous** les _named pipes_ avec la commande :

```cmd
.\accesschk.exe /accepteula \pipe\
```
{% endhint %}

<mark style="color:green;">**Reviewing LSASS Named Pipe Permissions**</mark>

```cmd-session
C:\htb> accesschk.exe /accepteula \\.\Pipe\lsass -v
```

***

### <mark style="color:red;">Named Pipes Attack Example</mark>

[WindscribeService Named Pipe Privilege Escalation](https://www.exploit-db.com/exploits/48021)&#x20;

&#x20;En utilisant `accesschk`, on peut lister tous les tuyaux qui permettent l’écriture avec la commande `accesschk.exe -w \pipe\* -v`, et constater que `WindscribeService` autorise la lecture et l’écriture à tous les utilisateurs authentifiés (`Everyone`).

<mark style="color:green;">**Checking WindscribeService Named Pipe Permissions**</mark>

```cmd-session
C:\htb> accesschk.exe -accepteula -w \pipe\WindscribeService -v
  RW Everyone
        FILE_ALL_ACCESS
```

From here, we could leverage these lax permissions to escalate privileges on the host to SYSTEM.
