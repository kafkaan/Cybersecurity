# Unquoted Service Path

### <mark style="color:red;">Unquoted Service Path</mark>

{% hint style="warning" %}
Lorsqu'un service est installé, la configuration du registre spécifie un chemin vers le binaire qui doit être exécuté au démarrage du service. Si ce binaire n'est pas encapsulé entre guillemets, Windows tentera de localiser le binaire dans différents dossiers. Prenez l'exemple de chemin binaire ci-dessous.
{% endhint %}

```
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

Windows décidera de la méthode d'exécution d'un programme en fonction de son extension de fichier, il n'est donc pas nécessaire de la spécifier. Windows tentera de charger les exécutables potentiels suivants dans l'ordre au démarrage du service, avec un .exe sous-entendu :

* C:\Program
* C:\Program Files
* C:\Program Files (x86)\System
* C:\Program Files (x86)\System Explorer\service\SystemExplorerService64

#### <mark style="color:green;">Interrogation du service</mark>

```
C:\htb> sc qc SystemExplorerHelpService
```

Si nous pouvons créer les fichiers suivants, nous pourrions détourner le binaire du service et obtenir l'exécution de commandes dans le contexte du service, dans ce cas, NT AUTHORITY\SYSTEM.

* C:\Program.exe\\
* C:\Program Files (x86)\System.exe

#### <mark style="color:green;">Recherche de chemins de service non encadrés de guillemets</mark>

{% code fullWidth="true" %}
```
C:\htb> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
GVFS.Service                                                                        GVFS.Service                              C:\Program Files\GVFS\GVFS.Service.exe                                                 Auto
System Explorer Service                                                             SystemExplorerHelpService                 C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe             Auto
WindscribeService                                                                   WindscribeService                         C:\Program Files (x86)\Windscribe\WindscribeService.exe                                  Auto
```
{% endcode %}
