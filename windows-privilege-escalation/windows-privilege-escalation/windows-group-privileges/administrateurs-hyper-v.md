# Administrateurs Hyper-V

{% hint style="warning" %}
Le groupe **Hyper-V Administrators** a un accès complet à toutes les fonctionnalités de **Hyper-V**. Si les **Contrôleurs de domaine** ont été virtualisés, les administrateurs de virtualisation devraient être considérés comme des **Domain Admins** (Administrateurs de domaine). Ils pourraient facilement créer un clone du Contrôleur de domaine actif et monter le disque virtuel hors ligne pour obtenir le fichier **NTDS.dit** et extraire les **hashes de mot de passe NTLM** pour tous les utilisateurs du domaine.

Il est également bien documenté sur ce blog que, lors de la suppression d'une machine virtuelle, **vmms.exe** tente de restaurer les permissions de fichiers originales sur le fichier **.vhdx** correspondant et le fait en tant que **NT AUTHORITY\SYSTEM**, sans imiter l'utilisateur. Nous pouvons supprimer le fichier **.vhdx** et créer un lien dur natif pour pointer ce fichier vers un fichier protégé du **SYSTÈME**, pour lequel nous aurons un accès complet.

Si le système d'exploitation est vulnérable à **CVE-2018-0952** ou **CVE-2019-0841**, nous pouvons exploiter cette vulnérabilité pour obtenir des privilèges **SYSTEM**. Sinon, nous pouvons essayer de profiter d'une application sur le serveur qui a installé un service exécuté dans le contexte de **SYSTEM**, lequel peut être démarré par des utilisateurs non privilégiés.
{% endhint %}

***

#### <mark style="color:green;">Fichier cible</mark>

An example of this is Firefox, which installs the `Mozilla Maintenance Service`. We can update [this exploit](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1) (a proof-of-concept for NT hard link) to grant our current user full permissions on the file below:

**C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe**

#### <mark style="color:green;">Prendre la propriété du fichier</mark>

{% code fullWidth="true" %}
```powershell
C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
{% endcode %}

#### <mark style="color:green;">Démarrer le service de maintenance Mozilla</mark>

Ensuite, nous pouvons remplacer ce fichier par un **maintenanceservice.exe** malveillant, démarrer le service de maintenance, et obtenir une exécution de commandes en tant que **SYSTEM**.

```powershell
C:\htb> sc.exe start MozillaMaintenance
```

***
