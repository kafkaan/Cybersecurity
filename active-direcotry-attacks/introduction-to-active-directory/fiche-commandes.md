# FICHE COMMANDES

***

### 🔗 1. Connexion RDP à la machine Windows (depuis Pwnbox)

```bash
xfreerdp /v:10.129.202.146 /u:htb-student_adm /p:Academy_student_DA! /cert:ignore
```

#### Explication :

* `/v:` → IP de la machine cible
* `/u:` → utilisateur AD
* `/p:` → mot de passe
* `/cert:ignore` → ignore les certificats auto-signés (normal en lab)

***

### 👤 2. Gestion des utilisateurs Active Directory

#### 📥 Importer le module Active Directory

```powershell
Import-Module ActiveDirectory
```

***

#### ➕ Créer un nouvel utilisateur AD

```powershell
New-ADUser `
-Name "Andromeda Cepheus" `
-GivenName "Andromeda" `
-Surname "Cepheus" `
-SamAccountName "acepheus" `
-UserPrincipalName "a.cepheus@inlanefreight.local" `
-EmailAddress "a.cepheus@inlanefreight.local" `
-DisplayName "Andromeda Cepheus" `
-Path "OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL" `
-AccountPassword (ConvertTo-SecureString "TempP@ss123!" -AsPlainText -Force) `
-Enabled $true `
-ChangePasswordAtLogon $true
```

#### Explication :

* `SamAccountName` → login Windows
* `UserPrincipalName` → email / login moderne
* `Path` → OU où créer l’utilisateur
* `ChangePasswordAtLogon $true` → oblige à changer le mot de passe

👉 À répéter pour :

* Orion Starchaser
* Artemis Callisto

***

#### ❌ Supprimer un utilisateur AD

```powershell
Remove-ADUser -Identity "Paul Valencia"
```

ou

```powershell
Remove-ADUser -Identity "Mike O'Hare"
```

⚠️ Demande confirmation avant suppression.

***

#### 🔓 Déverrouiller un compte utilisateur

```powershell
Unlock-ADAccount -Identity "amasters"
```

***

#### 🔑 Forcer un changement de mot de passe au prochain login

```powershell
Set-ADUser -Identity "amasters" -ChangePasswordAtLogon $true
```

***

### 🗂️ 3. Gestion des OU (Organizational Units)

#### ➕ Créer une nouvelle OU

```powershell
New-ADOrganizationalUnit `
-Name "Security Analysts" `
-Path "OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```

#### Explication :

* Les OU servent à organiser les utilisateurs et appliquer des GPO

***

### 👥 4. Gestion des groupes de sécurité

#### ➕ Créer un groupe de sécurité

```powershell
New-ADGroup `
-Name "Security Analysts" `
-SamAccountName "SecurityAnalysts" `
-GroupCategory Security `
-GroupScope Global `
-DisplayName "Security Analysts" `
-Path "OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL" `
-Description "Security Analysts under IT OU"
```

***

#### ➕ Ajouter des utilisateurs à un groupe

```powershell
Add-ADGroupMember `
-Identity "Security Analysts" `
-Members acepheus,ostarchaser,acallisto
```

***

### 🛡️ 5. Gestion des GPO (Group Policy Objects)

#### 📋 Copier une GPO existante

```powershell
Copy-GPO `
-SourceName "Logon Banner" `
-TargetName "Security Analysts Control"
```

#### Explication :

* Duplique une GPO existante pour la modifier sans risque

***

#### 🔗 Lier une GPO à une OU

```powershell
New-GPLink `
-Name "Security Analysts Control" `
-Target "OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL" `
-LinkEnabled Yes
```

***

#### 🔁 Réactiver un lien GPO (si déjà existant)

```powershell
Set-GPLink `
-Name "Security Analysts Control" `
-Target "OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL" `
-LinkEnabled Yes
```

***

### 💻 6. Commandes utiles de vérification

#### 📦 Lister les modules chargés

```powershell
Get-Module
```

***

#### 🔍 Voir toutes les commandes AD disponibles

```powershell
Get-Command -Module ActiveDirectory
```

***

#### 📖 Aide sur une commande

```powershell
Get-Help New-ADUser -Full
```

***

### 🧪 7. Commandes liées aux ordinateurs (pour la partie II)

#### ➕ Ajouter un PC au domaine

```powershell
Add-Computer `
-DomainName "INLANEFREIGHT.LOCAL" `
-Credential "INLANEFREIGHT\htb-student_adm" `
-Restart
```

***

#### 🔍 Vérifier un ordinateur dans l’AD

```powershell
Get-ADComputer -Identity "PC-NAME" -Properties * |
Select CN,CanonicalName,IPv4Address
```

***
