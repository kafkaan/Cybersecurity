# PowerShell Active Directory

## <mark style="color:red;">PowerShell Active Directory</mark>

### <mark style="color:blue;">Table des matières</mark>

1. Prérequis et Installation
2. Commandes de Base
3. Gestion des Utilisateurs
4. Gestion des Groupes
5. Gestion des Ordinateurs
6. Gestion des ACL (Permissions)
7. Recherche et Filtrage
8. Énumération et Reconnaissance
9. Techniques Offensives

***

### <mark style="color:blue;">Prérequis</mark>

#### <mark style="color:green;">Installation du module Active Directory</mark>

```powershell
# Vérifier si le module est installé
Get-Module -ListAvailable ActiveDirectory

# Installer le module (Windows 10/11)
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Importer le module
Import-Module ActiveDirectory
```

#### <mark style="color:green;">Se connecter à un domaine distant</mark>

```powershell
# Avec des credentials
$cred = Get-Credential
Get-ADUser -Filter * -Server "dc.domain.com" -Credential $cred

# Spécifier un contrôleur de domaine
$dcIP = "10.10.10.100"
Get-ADUser -Filter * -Server $dcIP
```

***

### <mark style="color:blue;">Commandes de Base</mark>

#### <mark style="color:green;">Informations sur le domaine</mark>

```powershell
# Obtenir le domaine actuel
Get-ADDomain

# Obtenir la forêt
Get-ADForest

# Lister tous les contrôleurs de domaine
Get-ADDomainController -Filter *

# Informations sur un DC spécifique
Get-ADDomainController -Identity "DC01"

# Obtenir le DN (Distinguished Name) du domaine
(Get-ADDomain).DistinguishedName
# Résultat : DC=sequel,DC=htb
```

#### <mark style="color:green;">Structure de base d'un DN</mark>

```
CN=Common Name (objet spécifique)
OU=Organizational Unit (unité d'organisation)
DC=Domain Component (partie du domaine)

Exemple complet :
CN=John Doe,OU=Users,OU=Paris,DC=company,DC=local
```

***

### <mark style="color:blue;">Gestion des Utilisateurs</mark>

#### <mark style="color:green;">Lister les utilisateurs</mark>

```powershell
# Tous les utilisateurs
Get-ADUser -Filter *

# Utilisateur spécifique
Get-ADUser -Identity "john.doe"
Get-ADUser -Identity "S-1-5-21-..." # Par SID

# Avec toutes les propriétés
Get-ADUser -Identity "john.doe" -Properties *

# Propriétés spécifiques
Get-ADUser -Identity "john.doe" -Properties Description,MemberOf,LastLogonDate
```

#### <mark style="color:green;">Créer un utilisateur</mark>

```powershell
# Création simple
New-ADUser -Name "Bob Martin" -SamAccountName "bob.martin" -UserPrincipalName "bob.martin@domain.com"

# Création complète
New-ADUser -Name "Alice Smith" `
    -GivenName "Alice" `
    -Surname "Smith" `
    -SamAccountName "alice.smith" `
    -UserPrincipalName "alice.smith@domain.com" `
    -Path "OU=Users,DC=domain,DC=com" `
    -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Enabled $true `
    -ChangePasswordAtLogon $true `
    -Description "Marketing Manager"
```

#### <mark style="color:green;">Modifier un utilisateur</mark>

```powershell
# Changer une propriété
Set-ADUser -Identity "john.doe" -Description "IT Admin"

# Changer le mot de passe
Set-ADAccountPassword -Identity "john.doe" -NewPassword (ConvertTo-SecureString "NewP@ss123" -AsPlainText -Force)

# Forcer le changement de mot de passe
Set-ADUser -Identity "john.doe" -ChangePasswordAtLogon $true

# Activer/Désactiver un compte
Enable-ADAccount -Identity "john.doe"
Disable-ADAccount -Identity "john.doe"

# Déverrouiller un compte
Unlock-ADAccount -Identity "john.doe"

# Ajouter à un groupe
Add-ADGroupMember -Identity "Admins" -Members "john.doe"
```

#### <mark style="color:green;">Supprimer un utilisateur</mark>

```powershell
# Supprimer
Remove-ADUser -Identity "john.doe"

# Sans confirmation
Remove-ADUser -Identity "john.doe" -Confirm:$false
```

#### <mark style="color:green;">Rechercher des utilisateurs</mark>

```powershell
# Par nom
Get-ADUser -Filter "Name -like '*John*'"

# Comptes actifs
Get-ADUser -Filter {Enabled -eq $true}

# Comptes désactivés
Get-ADUser -Filter {Enabled -eq $false}

# Par description
Get-ADUser -Filter "Description -like '*admin*'" -Properties Description

# Dernière connexion récente
Get-ADUser -Filter * -Properties LastLogonDate | Where-Object {$_.LastLogonDate -gt (Get-Date).AddDays(-30)}

# Comptes sans expiration de mot de passe
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires

# Utilisateurs avec SPN (pour Kerberoasting)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

***

### <mark style="color:blue;">Gestion des Groupes</mark>

#### <mark style="color:green;">Lister les groupes</mark>

```powershell
# Tous les groupes
Get-ADGroup -Filter *

# Groupe spécifique
Get-ADGroup -Identity "Domain Admins"

# Avec les membres
Get-ADGroup -Identity "Domain Admins" -Properties Members

# Groupes d'un utilisateur
Get-ADUser -Identity "john.doe" -Properties MemberOf | Select-Object -ExpandProperty MemberOf
```

#### <mark style="color:green;">Créer un groupe</mark>

```powershell
# Groupe de sécurité global
New-ADGroup -Name "IT Team" -GroupScope Global -GroupCategory Security -Path "OU=Groups,DC=domain,DC=com"

# Groupe de distribution
New-ADGroup -Name "Marketing List" -GroupScope Universal -GroupCategory Distribution
```

#### <mark style="color:green;">Gérer les membres</mark>

```powershell
# Ajouter un membre
Add-ADGroupMember -Identity "IT Team" -Members "john.doe"

# Ajouter plusieurs membres
Add-ADGroupMember -Identity "IT Team" -Members "john.doe","alice.smith","bob.martin"

# Retirer un membre
Remove-ADGroupMember -Identity "IT Team" -Members "john.doe"

# Lister les membres d'un groupe
Get-ADGroupMember -Identity "Domain Admins"

# De manière récursive (sous-groupes inclus)
Get-ADGroupMember -Identity "Domain Admins" -Recursive
```

#### <mark style="color:green;">Groupes privilégiés importants</mark>

```powershell
# Énumérer les groupes à hauts privilèges
$privilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Print Operators",
    "Server Operators",
    "Group Policy Creator Owners",
    "DnsAdmins"
)

foreach ($group in $privilegedGroups) {
    Write-Host "`n=== $group ===" -ForegroundColor Cyan
    Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
}
```

***

### <mark style="color:blue;">Gestion des Ordinateurs</mark>

#### <mark style="color:green;">Lister les ordinateurs</mark>

```powershell
# Tous les ordinateurs
Get-ADComputer -Filter *

# Avec propriétés
Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate

# Serveurs uniquement
Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Properties OperatingSystem

# Postes de travail
Get-ADComputer -Filter {OperatingSystem -like "*Windows 10*" -or OperatingSystem -like "*Windows 11*"} -Properties OperatingSystem
```

#### <mark style="color:green;">Créer/Modifier un ordinateur</mark>

```powershell
# Créer
New-ADComputer -Name "DESKTOP-001" -Path "OU=Workstations,DC=domain,DC=com"

# Modifier
Set-ADComputer -Identity "DESKTOP-001" -Description "IT Department PC"

# Supprimer
Remove-ADComputer -Identity "DESKTOP-001" -Confirm:$false
```

#### <mark style="color:green;">Informations utiles</mark>

```powershell
# Ordinateurs inactifs (pas de connexion depuis 90 jours)
$date = (Get-Date).AddDays(-90)
Get-ADComputer -Filter {LastLogonDate -lt $date} -Properties LastLogonDate | Select-Object Name,LastLogonDate

# Ordinateurs avec OS obsolète
Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object {$_.OperatingSystem -like "*Windows 7*" -or $_.OperatingSystem -like "*Windows XP*"}
```

***

### <mark style="color:blue;">Gestion des ACL (Permissions)</mark>

#### <mark style="color:green;">Concepts de base</mark>

```
ACL = Access Control List (liste de contrôle d'accès)
ACE = Access Control Entry (entrée de contrôle d'accès)
DACL = Discretionary ACL (permissions normales)
SACL = System ACL (audit)
```

#### <mark style="color:green;">Lire les ACL</mark>

```powershell
# Obtenir l'ACL d'un objet
$acl = Get-ACL "AD:\CN=Users,DC=domain,DC=com"
$acl

# Afficher les permissions
$acl.Access

# Voir le propriétaire
$acl.Owner

# ACL d'un utilisateur spécifique
$dn = (Get-ADUser "john.doe").DistinguishedName
$acl = Get-ACL "AD:\$dn"
$acl.Access | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType
```

#### <mark style="color:green;">Modifier le propriétaire (comme dans ton exemple)</mark>

```powershell
# Méthode 1 : Avec NTAccount
$objectDN = "CN=Certification Authority,CN=Users,DC=sequel,DC=htb"
$acl = Get-ACL "AD:\$objectDN"

# Créer l'identité
$identityReference = New-Object System.Security.Principal.NTAccount("sequel", "ryan")

# Définir le propriétaire
$acl.SetOwner($identityReference)

# Appliquer
Set-ACL -Path "AD:\$objectDN" -AclObject $acl

# Méthode 2 : Avec SID
$userSID = (Get-ADUser "ryan").SID
$identity = New-Object System.Security.Principal.SecurityIdentifier($userSID)
$acl.SetOwner($identity)
Set-ACL -Path "AD:\$objectDN" -AclObject $acl
```

#### <mark style="color:green;">Ajouter des permissions (GenericAll, WriteDACL, etc.)</mark>

```powershell
# Exemple complet : Donner GenericAll à un utilisateur
$objectDN = "CN=Certification Authority,CN=Users,DC=sequel,DC=htb"
$targetUser = "ryan"

# Obtenir l'ACL actuelle
$acl = Get-ACL "AD:\$objectDN"

# Obtenir le SID de l'utilisateur
$userSID = (Get-ADUser $targetUser).SID
$identity = New-Object System.Security.Principal.SecurityIdentifier($userSID)

# Définir les droits
$adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
$type = [System.Security.AccessControl.AccessControlType]::Allow
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All

# Créer la règle
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type, $inheritanceType)

# Ajouter la règle
$acl.AddAccessRule($rule)

# Appliquer
Set-ACL -Path "AD:\$objectDN" -AclObject $acl
```

#### <mark style="color:green;">Types de droits Active Directory</mark>

```powershell
# Liste des droits principaux
[System.DirectoryServices.ActiveDirectoryRights]::GenericAll        # Tous les droits
[System.DirectoryServices.ActiveDirectoryRights]::GenericRead       # Lecture
[System.DirectoryServices.ActiveDirectoryRights]::GenericWrite      # Écriture
[System.DirectoryServices.ActiveDirectoryRights]::WriteDacl         # Modifier les permissions
[System.DirectoryServices.ActiveDirectoryRights]::WriteOwner        # Changer le propriétaire
[System.DirectoryServices.ActiveDirectoryRights]::CreateChild       # Créer des objets enfants
[System.DirectoryServices.ActiveDirectoryRights]::DeleteChild       # Supprimer des objets enfants
[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight     # Droits étendus (reset password, etc.)
```

#### <mark style="color:green;">Donner des permissions spécifiques</mark>

```powershell
# Reset password (ForceChangePassword)
$objectDN = (Get-ADUser "target").DistinguishedName
$acl = Get-ACL "AD:\$objectDN"
$userSID = (Get-ADUser "attacker").SID
$identity = New-Object System.Security.Principal.SecurityIdentifier($userSID)

# GUID pour "User-Force-Change-Password"
$extendedRight = [GUID]"00299570-246d-11d0-a768-00aa006e0529"

$adRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
$type = [System.Security.AccessControl.AccessControlType]::Allow
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None

$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type, $extendedRight, $inheritanceType)
$acl.AddAccessRule($rule)
Set-ACL -Path "AD:\$objectDN" -AclObject $acl
```

#### <mark style="color:green;">Supprimer une permission</mark>

```powershell
# Retirer une règle spécifique
$acl = Get-ACL "AD:\$objectDN"
$ruleToRemove = $acl.Access | Where-Object {$_.IdentityReference -eq "DOMAIN\ryan"}
foreach ($rule in $ruleToRemove) {
    $acl.RemoveAccessRule($rule)
}
Set-ACL -Path "AD:\$objectDN" -AclObject $acl
```

***

### <mark style="color:blue;">Recherche et Filtrage</mark>

#### <mark style="color:green;">Syntaxe des filtres</mark>

```powershell
# Opérateurs
-eq     # égal à
-ne     # différent de
-like   # contient (avec wildcards * et ?)
-notlike # ne contient pas
-gt     # supérieur à
-lt     # inférieur à
-and    # ET logique
-or     # OU logique

# Exemples
Get-ADUser -Filter "Name -eq 'John Doe'"
Get-ADUser -Filter "Name -like '*admin*' -and Enabled -eq $true"
Get-ADUser -Filter {(Description -like "*IT*") -or (Title -like "*Manager*")}
```

#### <mark style="color:green;">Recherches avancées avec LDAP</mark>

```powershell
# Avec LDAPFilter
Get-ADUser -LDAPFilter "(description=*admin*)"

# Utilisateurs avec SPN
Get-ADUser -LDAPFilter "(servicePrincipalName=*)"

# Groupes commençant par "Admin"
Get-ADGroup -LDAPFilter "(cn=Admin*)"

# Combinaison
Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(description=*admin*))"
```

#### <mark style="color:green;">Recherche dans toute la forêt</mark>

```powershell
# Obtenir tous les domaines de la forêt
$forest = Get-ADForest
$domains = $forest.Domains

# Chercher dans tous les domaines
foreach ($domain in $domains) {
    Write-Host "`n=== $domain ===" -ForegroundColor Green
    Get-ADUser -Filter {Name -like "*admin*"} -Server $domain
}
```

***

### <mark style="color:blue;">Énumération et Reconnaissance</mark>

#### <mark style="color:green;">Énumération complète du domaine</mark>

```powershell
# Informations générales
$domain = Get-ADDomain
Write-Host "Domain: $($domain.DNSRoot)"
Write-Host "Domain SID: $($domain.DomainSID)"
Write-Host "NetBIOS: $($domain.NetBIOSName)"
Write-Host "Forest: $($domain.Forest)"

# Contrôleurs de domaine
Get-ADDomainController -Filter * | Select-Object Name,IPv4Address,OperatingSystem

# Politique de mots de passe
Get-ADDefaultDomainPasswordPolicy

# Trusts (relations d'approbation)
Get-ADTrust -Filter *
```

#### <mark style="color:green;">Trouver les utilisateurs sensibles</mark>

```powershell
# Administrateurs du domaine
Get-ADGroupMember "Domain Admins"

# Utilisateurs avec des privilèges élevés
$sensitiveGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators")
foreach ($group in $sensitiveGroups) {
    Write-Host "`n=== $group ===" -ForegroundColor Red
    Get-ADGroupMember $group -Recursive | Select-Object Name,SamAccountName,DistinguishedName
}

# Comptes de service (pour Kerberoasting)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,LastLogonDate | 
    Select-Object Name,SamAccountName,ServicePrincipalName,LastLogonDate

# Comptes avec délégation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Comptes avec mot de passe non requis
Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties PasswordNotRequired

# Comptes avec mot de passe qui n'expire jamais
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires,PasswordLastSet
```

#### <mark style="color:green;">GPO (Group Policy Objects)</mark>

```powershell
# Lister toutes les GPO
Get-GPO -All

# GPO appliquées à une OU
Get-GPInheritance -Target "OU=Users,DC=domain,DC=com"

# Détails d'une GPO
Get-GPO -Name "Default Domain Policy" | Select-Object *

# Rapport HTML d'une GPO
Get-GPOReport -Name "Default Domain Policy" -ReportType HTML -Path "C:\report.html"
```

#### <mark style="color:green;">Énumération des partages</mark>

```powershell
# Partages réseau sur les ordinateurs du domaine
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

foreach ($computer in $computers) {
    try {
        Write-Host "`n=== $computer ===" -ForegroundColor Cyan
        Get-WmiObject -Class Win32_Share -ComputerName $computer -ErrorAction Stop | 
            Select-Object Name,Path,Description
    } catch {
        Write-Host "Impossible d'accéder à $computer" -ForegroundColor Red
    }
}
```

***

### <mark style="color:blue;">Techniques Offensives</mark>

#### <mark style="color:green;">Énumération des ACL dangereuses</mark>

```powershell
# Trouver qui a WriteDACL sur des objets sensibles
$sensitiveObjects = @(
    "CN=Domain Admins,CN=Users,DC=domain,DC=com",
    "CN=Enterprise Admins,CN=Users,DC=domain,DC=com",
    "CN=Administrators,CN=Builtin,DC=domain,DC=com"
)

foreach ($obj in $sensitiveObjects) {
    $acl = Get-ACL "AD:\$obj"
    Write-Host "`n=== $obj ===" -ForegroundColor Yellow
    $acl.Access | Where-Object {
        $_.ActiveDirectoryRights -match "WriteDacl|WriteOwner|GenericAll"
    } | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType
}
```

#### <mark style="color:green;">Chercher les mots de passe dans les descriptions</mark>

```powershell
# Descriptions suspectes
Get-ADUser -Filter * -Properties Description | 
    Where-Object {$_.Description -match "password|pwd|pass|mdp|secret|cred"} |
    Select-Object Name,Description

# Idem pour les ordinateurs
Get-ADComputer -Filter * -Properties Description | 
    Where-Object {$_.Description -match "password|pwd|pass|mdp|secret|cred"} |
    Select-Object Name,Description
```

#### <mark style="color:green;">ASREP Roasting (comptes sans pré-auth Kerberos)</mark>

```powershell
# Trouver les comptes vulnérables
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth,ServicePrincipalName
```

#### <mark style="color:green;">Énumération des sessions</mark>

```powershell
# Voir qui est connecté où (nécessite des privilèges)
Import-Module ActiveDirectory

$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty DNSHostName

foreach ($computer in $computers) {
    try {
        $sessions = qwinsta /server:$computer 2>$null
        if ($sessions) {
            Write-Host "`n=== $computer ===" -ForegroundColor Green
            $sessions
        }
    } catch {}
}
```

#### <mark style="color:green;">Exportation massive de données</mark>

```powershell
# Exporter tous les utilisateurs en CSV
Get-ADUser -Filter * -Properties * | 
    Export-Csv -Path "C:\users_export.csv" -NoTypeInformation

# Exporter tous les groupes et leurs membres
$groups = Get-ADGroup -Filter *
$results = @()

foreach ($group in $groups) {
    $members = Get-ADGroupMember -Identity $group.Name
    foreach ($member in $members) {
        $results += [PSCustomObject]@{
            GroupName = $group.Name
            MemberName = $member.Name
            MemberType = $member.ObjectClass
        }
    }
}
$results | Export-Csv -Path "C:\groups_export.csv" -NoTypeInformation

# Exporter la structure AD complète
Get-ADObject -Filter * -Properties * | 
    Export-Clixml -Path "C:\ad_dump.xml"
```

***

### <mark style="color:blue;">Astuces et Bonnes Pratiques</mark>

#### <mark style="color:green;">Gestion des erreurs</mark>

```powershell
# Ignorer les erreurs
Get-ADUser -Identity "nonexistent" -ErrorAction SilentlyContinue

# Capturer les erreurs
try {
    Get-ADUser -Identity "john.doe"
} catch {
    Write-Host "Erreur: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### <mark style="color:green;">Performance</mark>

```powershell
# Limiter les propriétés chargées
Get-ADUser -Filter * -Properties Name,SamAccountName  # Rapide
Get-ADUser -Filter * -Properties *                    # Lent

# Limiter le nombre de résultats
Get-ADUser -Filter * -ResultSetSize 100

# Utiliser -SearchBase pour limiter la portée
Get-ADUser -Filter * -SearchBase "OU=IT,DC=domain,DC=com"
```

#### <mark style="color:green;">Scripting avancé</mark>

```powershell
# Créer plusieurs utilisateurs depuis un CSV
$users = Import-Csv "C:\users.csv"
# CSV: Name,FirstName,LastName,SamAccountName,Password

foreach ($user in $users) {
    $securePass = ConvertTo-SecureString $user.Password -AsPlainText -Force
    New-ADUser -Name $user.Name `
        -GivenName $user.FirstName `
        -Surname $user.LastName `
        -SamAccountName $user.SamAccountName `
        -AccountPassword $securePass `
        -Enabled $true
    Write-Host "Créé: $($user.Name)" -ForegroundColor Green
}
```

#### <mark style="color:green;">Commandes utiles pour le pentest</mark>

```powershell
# BloodHound friendly export
Get-ADUser -Filter * -Properties * | ConvertTo-Json | Out-File "users.json"
Get-ADComputer -Filter * -Properties * | ConvertTo-Json | Out-File "computers.json"
Get-ADGroup -Filter * -Properties * | ConvertTo-Json | Out-File "groups.json"

# Chercher des chemins d'attaque potentiels
# Qui peut modifier les GPO ?
Get-GPO -All | ForEach-Object {
    $gpo = $_
    $acl = Get-GPPermission -Guid $gpo.Id -All
    $acl | Where-Object {$_.Permission -match "Edit"} | 
        Select-Object @{N='GPO';E={$gpo.DisplayName}}, Trustee, Permission
}
```

***
