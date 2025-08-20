# Printer Bug

### <mark style="color:blue;">Printer Bug</mark>

{% hint style="warning" %}
**Le Printer Bug** est une vulnérabilité dans un protocole utilisé par Windows pour gérer les impressions. En gros, ce protocole permet à un ordinateur (le client) de parler avec un autre ordinateur qui gère les impressions (le serveur d'impression).

***

* **Protocole MS-RPRN (Print System Remote Protocol)** :\
  C'est un ensemble de règles qui permettent à un ordinateur de communiquer avec un serveur d'impression pour envoyer des travaux d'impression et gérer la file d'attente d'impression.
* **Spooler** :\
  C'est le service qui s'occupe de gérer les travaux d'impression sur un ordinateur. Imagine-le comme un "assistant d'impression" qui reçoit et organise les tâches d'impression.
* **Named Pipe** :\
  C'est un moyen de communication entre deux programmes sur le même ordinateur (ou entre ordinateurs). Tu peux l'imaginer comme un tuyau nommé qui permet le passage d'informations d'un programme à un autre.
* **RpcOpenPrinter** :\
  C'est une fonction (ou une commande) utilisée pour ouvrir une connexion avec le service d'impression (spooler). Elle permet à un programme de dire "Je veux parler au service d'impression".
* **RpcRemoteFindFirstPrinterChangeNotificationEx** :\
  C'est une autre fonction utilisée pour demander au serveur d'impression de notifier un changement (par exemple, quand une nouvelle tâche d'impression arrive). Elle est normalement utilisée pour surveiller l'état de l'imprimante.
* **SMB (Server Message Block)** :\
  C'est un protocole de communication utilisé par Windows pour partager des fichiers, imprimantes et autres ressources entre ordinateurs sur un réseau.
{% endhint %}

Le **Printer Bug** est une faille dans le protocole **MS-RPRN** (**Print System Remote Protocol**).

Ce protocole définit la communication du traitement des tâches d'impression et de la gestion du système d'impression entre un client et un serveur d'impression.

Pour exploiter cette faille, tout utilisateur du domaine peut se connecter à la **named pipe** du **spooler** avec la méthode **RpcOpenPrinter** et utiliser la méthode **RpcRemoteFindFirstPrinterChangeNotificationEx**, forçant ainsi le serveur à s'authentifier auprès de n'importe quel hôte fourni par le client via **SMB**.

Le service **spooler** s'exécute sous **SYSTEM** et est installé par défaut sur les **serveurs Windows** exécutant **Desktop Experience**.

Cette attaque peut être utilisée pour relayer vers **LDAP** et accorder à un compte attaquant les privilèges **DCSync**, lui permettant de récupérer tous les **hashs de mots de passe** d'Active Directory.

L'attaque peut également être utilisée pour relayer l'authentification LDAP et accorder des **privilèges de délégation restreinte basée sur les ressources (RBCD)** à la victime vers un compte machine sous notre contrôle, donnant ainsi à l'attaquant la possibilité de s'authentifier en tant que **n'importe quel utilisateur** sur l'ordinateur de la victime.

Cette attaque peut être exploitée pour **compromettre un contrôleur de domaine** dans un **domaine/forêt partenaire**, à condition que l'attaquant ait déjà un **accès administrateur** à un **contrôleur de domaine** dans la première forêt/domaine et que la relation de confiance autorise la **délégation TGT**, ce qui n'est plus activé par défaut.

Nous pouvons utiliser des outils comme le **module Get-SpoolStatus** de cet outil (qui peut être trouvé sur la cible générée) ou cet outil pour vérifier la présence de machines vulnérables au **Printer Bug (MS-PRN)**.

Cette faille peut être utilisée pour compromettre un hôte dans une autre forêt où la **délégation non contrainte (Unconstrained Delegation)** est activée, comme un **contrôleur de domaine**.

Elle peut nous aider à **attaquer à travers les relations de confiance entre forêts** une fois qu'une forêt a été compromise.

<mark style="color:green;">**Enumerating for MS-PRN Printer Bug**</mark>

```powershell-session
PS C:\htb> Import-Module .\SecurityAssessment.ps1
PS C:\htb> Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

ComputerName                        Status
------------                        ------
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True
```
