# Windows Internals

## Windows Internals - Comment Windows fonctionne vraiment 🪟

### Table des matières

1. DLL - Dynamic Link Library
2. COM - Component Object Model
3. CLSID - Class Identifier
4. Le Registre Windows
5. Shell Extensions
6. Comment tout ça fonctionne ensemble

***

### 1. DLL - Dynamic Link Library 📚

#### C'est quoi une DLL ? 🤔

Une **DLL** (Dynamic Link Library) = Une bibliothèque de code partagée.

#### Analogie simple 🏠

Imagine une bibliothèque publique :

```
┌─────────────────────────────────────────┐
│         BIBLIOTHÈQUE MUNICIPALE         │
├─────────────────────────────────────────┤
│ • Romans (fiction.dll)                  │
│ • Encyclopédies (knowledge.dll)         │
│ • Manuels techniques (tech.dll)         │
└─────────────────────────────────────────┘
         ↑               ↑              ↑
    Restaurant      Étudiant        Mécanicien
   (cherche une    (cherche une    (cherche un
    recette)        définition)      manuel)
```

Au lieu que chaque personne **possède** tous les livres chez elle, ils viennent tous **emprunter** à la bibliothèque.

#### Dans Windows

```
┌─────────────────────────────────────────┐
│          DOSSIER SYSTEM32               │
├─────────────────────────────────────────┤
│ • kernel32.dll (fonctions système)      │
│ • user32.dll (interface utilisateur)    │
│ • gdi32.dll (graphiques)                │
│ • 7-zip.dll (compression)               │
└─────────────────────────────────────────┘
         ↑               ↑              ↑
    Programme A    Programme B    Programme C
     (utilise        (utilise       (utilise
      kernel32)       user32)        7-zip)
```

#### Pourquoi utiliser des DLL ? 💡

**Avantage 1 : Économie d'espace**

```
SANS DLL :
Programme A : 50 MB (inclut le code de compression)
Programme B : 50 MB (inclut le code de compression)
Programme C : 50 MB (inclut le code de compression)
Total : 150 MB

AVEC DLL :
Programme A : 2 MB
Programme B : 2 MB  
Programme C : 2 MB
compression.dll : 5 MB (partagée par tous)
Total : 11 MB
```

**Avantage 2 : Mises à jour faciles**

```
Si un bug est trouvé dans le code de compression :

SANS DLL : Mettre à jour A, B, C séparément (3 mises à jour)
AVEC DLL : Mettre à jour compression.dll uniquement (1 mise à jour)
```

**Avantage 3 : Code réutilisable**

```
Développeur 1 crée compression.dll
    ↓
Développeurs 2, 3, 4... utilisent compression.dll
(pas besoin de réinventer la roue)
```

#### Types de DLL

**1. DLL système (Windows)**

```
C:\Windows\System32\
├── kernel32.dll     → Opérations système de base
├── user32.dll       → Interface utilisateur
├── ntdll.dll        → Interface noyau Windows
└── shell32.dll      → Explorateur Windows
```

**2. DLL d'application**

```
C:\Program Files\7-Zip\
└── 7-zip.dll        → Fonctions de compression 7-Zip

C:\Program Files\Adobe\
└── Photoshop.dll    → Fonctions Photoshop
```

#### Comment une DLL est chargée ? ⚙️

```
┌──────────────────────────────────────────────────────┐
│ 1. Programme démarre                                 │
│    notepad.exe lance                                 │
└──────────────────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────────────────┐
│ 2. Windows regarde : "Quelles DLL notepad a besoin ?"│
│    → kernel32.dll                                    │
│    → user32.dll                                      │
│    → gdi32.dll                                       │
└──────────────────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────────────────┐
│ 3. Windows charge ces DLL en mémoire                 │
│    Les fonctions deviennent disponibles              │
└──────────────────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────────────────┐
│ 4. Notepad appelle les fonctions des DLL            │
│    CreateWindow() depuis user32.dll                  │
│    DrawText() depuis gdi32.dll                       │
└──────────────────────────────────────────────────────┘
```

#### Exemple concret 💻

```c
// Dans un programme C
#include <windows.h>

int main() {
    // Cette fonction vient de user32.dll
    MessageBox(NULL, "Hello!", "Title", MB_OK);
    //    ↑
    // Windows charge automatiquement user32.dll
    // et appelle la fonction MessageBox
    
    return 0;
}
```

***

### 2. COM - Component Object Model 🧩

#### C'est quoi COM ? 🤔

**COM** = Un système qui permet à différents programmes de **communiquer entre eux** et de **partager du code**, même s'ils sont écrits dans des langages différents.

#### Analogie : Les prises électriques 🔌

```
┌────────────────────────────────────────────────┐
│        PRISE ÉLECTRIQUE STANDARD               │
│                                                │
│  Peu importe l'appareil :                     │
│  • Lampe                                       │
│  • Ordinateur                                  │
│  • Téléphone                                   │
│                                                │
│  Tous utilisent la MÊME PRISE !               │
│  = Interface standardisée                      │
└────────────────────────────────────────────────┘
```

Dans Windows, COM fait pareil mais pour le **code** :

```
┌────────────────────────────────────────────────┐
│             INTERFACE COM                      │
│                                                │
│  Peu importe le programme :                   │
│  • Excel (écrit en C++)                       │
│  • Word (écrit en C++)                        │
│  • Script Python                               │
│  • Programme Visual Basic                      │
│                                                │
│  Tous peuvent utiliser les MÊMES composants ! │
└────────────────────────────────────────────────┘
```

#### Exemple concret : Excel dans Word 📊

Quand tu insères un tableau Excel dans Word :

```
┌─────────────────────────────────────────────────┐
│ 1. Word dit : "J'ai besoin d'Excel"            │
│    via l'interface COM                          │
└─────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────┐
│ 2. Windows charge le composant COM Excel        │
│    (Excel.Application)                          │
└─────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────┐
│ 3. Word peut maintenant appeler les fonctions  │
│    Excel sans savoir comment Excel fonctionne   │
│    CreateWorksheet()                            │
│    AddChart()                                   │
└─────────────────────────────────────────────────┘
```

#### Les composants COM 🧱

Un **composant COM** = Un morceau de code réutilisable avec une **interface standardisée**.

```
┌──────────────────────────────────┐
│     COMPOSANT COM : 7-Zip        │
├──────────────────────────────────┤
│ Interface publique :             │
│ • Extract(fichier, destination)  │
│ • Compress(fichiers, archive)    │
│ • ListFiles(archive)             │
│                                  │
│ Implémentation cachée :          │
│ • [code complexe de compression] │
└──────────────────────────────────┘
```

#### Où vivent les composants COM ? 🏠

Dans le **registre Windows** (on y revient après).

```
Registre Windows
    └── CLSID (identifiants)
          └── {23170F69-...} (7-Zip)
                ├── Nom : "7-Zip Shell Extension"
                ├── Fichier : C:\Program Files\7-Zip\7-zip.dll
                └── Type : InProcServer32
```

#### Types de serveurs COM

**1. In-Process Server (InProcServer32)**

```
┌────────────────────────────────┐
│   Programme principal          │
│   ┌────────────────────┐      │
│   │  Code du programme │      │
│   ├────────────────────┤      │
│   │  DLL COM chargée   │ ←─── Même processus
│   │  (dans la mémoire) │      │
│   └────────────────────┘      │
└────────────────────────────────┘

Avantage : Très rapide (même mémoire)
Exemple : 7-zip.dll, extensions shell
```

**2. Out-Of-Process Server (LocalServer32)**

```
┌──────────────────┐       ┌──────────────────┐
│  Programme       │       │  Serveur COM     │
│  principal       │◄─────►│  séparé          │
│                  │  IPC  │  (Excel.exe)     │
└──────────────────┘       └──────────────────┘

Avantage : Isolation (si crash, n'affecte pas l'autre)
Exemple : Excel Automation
```

***

### 3. CLSID - Class Identifier 🆔

#### C'est quoi un CLSID ? 🤔

Un **CLSID** = Un **numéro d'identification unique** (comme un passeport) pour chaque composant COM.

#### Format d'un CLSID

```
{23170F69-40C1-278A-1000-000100020000}
 └────┬────┘ └─┬─┘ └─┬─┘ └─┬─┘ └─────┬─────┘
      │        │      │      │         │
   8 chars  4 chars 4 chars 4 chars 12 chars
   
= 128 bits = GUID (Globally Unique Identifier)
```

#### Pourquoi des CLSID ? 💡

Sans CLSID :

```
Programme : "J'ai besoin de 7-Zip"
Windows : "Lequel ? Il y en a peut-être 10 versions !"
```

Avec CLSID :

```
Programme : "J'ai besoin du composant {23170F69-40C1-278A-1000-000100020000}"
Windows : "OK, c'est 7-Zip version X.Y, voilà !"
```

#### Analogie : Numéro de sécurité sociale 🎫

```
Personne A : "Je m'appelle Jean Martin"
Gouvernement : "Il y a 1000 Jean Martin, lequel êtes-vous ?"

Personne A : "Mon numéro est 1-85-06-75-123-456-78"
Gouvernement : "Ah, VOUS ! Jean Martin né le 06/06/1985 à Paris"
                     ↑
            Identification UNIQUE
```

#### CLSID dans le registre 🗂️

```
HKEY_CLASSES_ROOT\CLSID\
    └── {23170F69-40C1-278A-1000-000100020000}
          ├── (Default) = "7-Zip Shell Extension"
          ├── InProcServer32
          │     └── (Default) = "C:\Program Files\7-Zip\7-zip.dll"
          │     └── ThreadingModel = "Apartment"
          └── ProgID = "7-Zip"
```

**Lecture** :

* **CLSID** : {23170F69...} = Identifiant unique
* **Nom** : "7-Zip Shell Extension" = Nom humain
* **Fichier** : C:\Program Files\7-Zip\7-zip.dll = Où est le code
* **Type** : InProcServer32 = DLL chargée dans le processus

***

### 4. Le Registre Windows 📋

#### C'est quoi le registre ? 🤔

Le **registre Windows** = Une **énorme base de données hiérarchique** qui stocke TOUTES les configurations de Windows et des applications.

#### Analogie : L'annuaire téléphonique de Windows 📞

```
┌─────────────────────────────────────────┐
│      ANNUAIRE WINDOWS (Registre)        │
├─────────────────────────────────────────┤
│                                         │
│ 7-Zip :                                 │
│   Adresse : C:\Program Files\7-Zip\    │
│   DLL : 7-zip.dll                       │
│   Version : 22.01                       │
│   CLSID : {23170F69-...}               │
│                                         │
│ Word :                                  │
│   Adresse : C:\Program Files\Office\   │
│   CLSID : {000209FF-...}               │
│                                         │
│ Extensions de fichiers :                │
│   .txt → Notepad                        │
│   .zip → 7-Zip                          │
│   .docx → Word                          │
│                                         │
└─────────────────────────────────────────┘
```

#### Structure du registre 🌳

```
Registre Windows
│
├── HKEY_CLASSES_ROOT (HKCR)
│     └── Associations fichiers, COM, CLSID
│
├── HKEY_CURRENT_USER (HKCU)
│     └── Paramètres de l'utilisateur actuel
│
├── HKEY_LOCAL_MACHINE (HKLM)
│     └── Paramètres de la machine (tous utilisateurs)
│
├── HKEY_USERS (HKU)
│     └── Paramètres de tous les utilisateurs
│
└── HKEY_CURRENT_CONFIG (HKCC)
      └── Configuration matérielle actuelle
```

#### HKEY\_CLASSES\_ROOT (HKCR) - Le plus important pour COM

```
HKCR\
├── CLSID\                          ← TOUS les composants COM
│   ├── {23170F69-...}\             ← 7-Zip
│   │     └── InProcServer32
│   │           └── (Default) = "C:\Program Files\7-Zip\7-zip.dll"
│   │
│   └── {000209FF-...}\             ← Word
│         └── LocalServer32
│               └── (Default) = "C:\Program Files\Office\WINWORD.EXE"
│
├── .zip\                           ← Extension .zip
│   ├── (Default) = "7-Zip.zip"
│   └── shell\
│         └── open\
│               └── command = "C:\Program Files\7-Zip\7zFM.exe %1"
│
├── Directory\                      ← Dossiers
│   └── shellex\                    ← Extensions shell
│         └── ContextMenuHandlers\  ← Menus contextuels
│               └── 7-Zip\
│                     └── (Default) = "{23170F69-...}"
│
└── *\                              ← Tous fichiers
      └── shellex\
            └── ContextMenuHandlers\
                  └── 7-Zip\
                        └── (Default) = "{23170F69-...}"
```

#### Comment Windows utilise le registre ⚙️

**Exemple 1 : Double-clic sur fichier.zip**

```
┌────────────────────────────────────────────┐
│ 1. Tu double-cliques sur "archive.zip"    │
└────────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 2. Windows regarde dans le registre :     │
│    HKCR\.zip\(Default) = "7-Zip.zip"     │
└────────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 3. Windows cherche "7-Zip.zip" :          │
│    HKCR\7-Zip.zip\shell\open\command      │
│    = "C:\Program Files\7-Zip\7zFM.exe %1" │
└────────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 4. Windows lance :                         │
│    7zFM.exe "archive.zip"                  │
└────────────────────────────────────────────┘
```

**Exemple 2 : Clic droit sur dossier**

```
┌────────────────────────────────────────────┐
│ 1. Tu fais clic droit sur un dossier      │
└────────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 2. Windows regarde :                       │
│    HKCR\Directory\shellex\                │
│    ContextMenuHandlers\                    │
│    Trouve : 7-Zip, WinRAR, TortoiseSVN... │
└────────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 3. Pour 7-Zip, lit le CLSID :             │
│    {23170F69-...}                         │
└────────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 4. Cherche ce CLSID :                      │
│    HKCR\CLSID\{23170F69-...}\             │
│    InProcServer32 = "7-zip.dll"           │
└────────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 5. Charge 7-zip.dll                        │
│    Affiche les options 7-Zip dans le menu │
└────────────────────────────────────────────┘
```

***

### 5. Shell Extensions 🐚

#### C'est quoi une Shell Extension ? 🤔

Une **Shell Extension** = Un programme qui **étend les fonctionnalités** de l'Explorateur Windows.

#### Types de Shell Extensions

**1. Context Menu Handler (Menu contextuel)**

```
Clic droit sur fichier/dossier → Options supplémentaires

Exemple :
┌──────────────────────┐
│ Ouvrir               │
│ ──────────────────── │
│ ► 7-Zip              │ ← Ajouté par 7-Zip
│   • Extraire ici     │
│   • Ouvrir l'archive │
│ ──────────────────── │
│ Copier               │
│ Supprimer            │
└──────────────────────┘
```

**2. Icon Handler (Icônes personnalisées)**

```
.zip → 📦 (icône 7-Zip)
.rar → 📚 (icône WinRAR)
.git → 🔀 (icône TortoiseGit)
```

**3. Property Sheet Handler (Onglets propriétés)**

```
Clic droit → Propriétés
┌─────────────────────────────┐
│ Général │ 7-Zip │ Sécurité │ ← Onglet ajouté par 7-Zip
└─────────────────────────────┘
```

**4. Overlay Icon Handler (Icônes de superposition)**

```
✓ fichier.txt  ← Icône verte (synchronisé Dropbox)
↻ photo.jpg    ← Icône orange (en cours de sync)
✗ doc.docx     ← Icône rouge (conflit)
```

#### Comment enregistrer une Shell Extension ? 📝

```
HKCR\
└── Directory\               ← Pour les dossiers
    └── shellex\
        └── ContextMenuHandlers\
            └── MonExtension\
                └── (Default) = "{MON-CLSID-...}"

HKCR\
└── CLSID\
    └── {MON-CLSID-...}\
        └── InProcServer32
            └── (Default) = "C:\Path\To\MyDLL.dll"
```

***

### 6. Comment tout ça fonctionne ensemble 🔗

#### Scénario complet : Clic droit sur dossier avec 7-Zip

```
┌──────────────────────────────────────────────────────────┐
│ ÉTAPE 1 : Action utilisateur                             │
│ Tu fais clic droit sur un dossier                        │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ ÉTAPE 2 : Explorer.exe demande à Windows                │
│ "Quelles extensions shell sont enregistrées pour         │
│  les dossiers ?"                                         │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ ÉTAPE 3 : Windows consulte le REGISTRE                  │
│ HKCR\Directory\shellex\ContextMenuHandlers\              │
│ Trouve plusieurs entrées :                              │
│ • 7-Zip → {23170F69-40C1-278A-1000-000100020000}        │
│ • WinRAR → {B41DB860-...}                               │
│ • TortoiseSVN → {30351346-...}                          │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ ÉTAPE 4 : Pour chaque CLSID, Windows cherche la DLL    │
│ HKCR\CLSID\{23170F69-...}\InProcServer32                │
│ (Default) = "C:\Program Files\7-Zip\7-zip.dll"          │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ ÉTAPE 5 : Windows CHARGE la DLL en mémoire             │
│ LoadLibrary("C:\Program Files\7-Zip\7-zip.dll")        │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ ÉTAPE 6 : Windows APPELLE la fonction COM              │
│ IContextMenu::QueryContextMenu()                        │
│ → La DLL retourne les éléments de menu :               │
│   • "Extraire ici"                                      │
│   • "Extraire vers..."                                  │
│   • "Compresser et envoyer..."                          │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ ÉTAPE 7 : Windows AFFICHE le menu contextuel           │
│ ┌──────────────────────┐                               │
│ │ Ouvrir               │                               │
│ │ ► 7-Zip              │                               │
│ │   • Extraire ici     │ ← Vient de 7-zip.dll         │
│ │   • Extraire vers... │                               │
│ └──────────────────────┘                               │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ ÉTAPE 8 : Tu cliques sur "Extraire ici"                │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ ÉTAPE 9 : Windows appelle                               │
│ IContextMenu::InvokeCommand()                           │
│ → La DLL 7-zip.dll exécute le code d'extraction        │
└──────────────────────────────────────────────────────────┘
```

#### Schéma récapitulatif des concepts 🎨

```
┌─────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE WINDOWS                      │
│                                                              │
│  ┌────────────────────────────────────────────────┐        │
│  │              REGISTRE WINDOWS                  │        │
│  │  (Annuaire / Base de données)                  │        │
│  │                                                 │        │
│  │  HKCR\CLSID\{23170F69-...}\                   │        │
│  │    InProcServer32 = "7-zip.dll"               │        │
│  │           ↓                                    │        │
│  │     Stocke l'adresse                          │        │
│  └────────────────────────────────────────────────┘        │
│                    ↓                                        │
│  ┌────────────────────────────────────────────────┐        │
│  │         COMPOSANT COM (7-Zip)                  │        │
│  │  Identifié par CLSID : {23170F69-...}         │        │
│  │                                                 │        │
│  │  Interface COM standardisée :                  │        │
│  │  • IContextMenu                                │        │
│  │  • IShellExtInit                               │        │
│  │           ↓                                    │        │
│  │  Implémenté dans une DLL                      │        │
│  └────────────────────────────────────────────────┘        │
│                    ↓                                        │
│  ┌────────────────────────────────────────────────┐        │
│  │         DLL (7-zip.dll)                        │        │
│  │  Bibliothèque de code partagée                │        │
│  │                                                 │        │
│  │  Contient :                                    │        │
│  │  • Code de compression                         │        │
│  │  • Interface menu contextuel                   │        │
│  │  • Icônes                                      │        │
│  └────────────────────────────────────────────────┘        │
│                    ↓                                        │
│  ┌────────────────────────────────────────────────┐        │
│  │    SHELL EXTENSION (Menu contextuel)           │        │
│  │  Enregistré dans :                             │        │
│  │  HKCR\Directory\shellex\ContextMenuHandlers\  │        │
│  │                                                 │        │
│  │  Permet d'étendre l'Explorateur Windows       │        │
│  └────────────────────────────────────────────────┘        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

***

### Résumé final en analogies 🎯

#### 1. DLL = Bibliothèque municipale

```
Les programmes empruntent du code au lieu de tout avoir chez eux
```

#### 2. COM = Prise électrique universelle

```
Interface standardisée pour que différents programmes communiquent
```

#### 3. CLSID = Passeport / Numéro de sécurité sociale

```
Identifiant unique pour chaque composant COM
```

#### 4. Registre = Annuaire téléphonique géant

```
Base de données qui stocke où trouver chaque composant
```

#### 5. Shell Extension = Plugin pour Explorateur Windows

```
Ajoute des fonctionnalités au menu clic droit, aux icônes, etc.
```

***

### Flow chart complet 🌊

```
TU (utilisateur)
    ↓
Fait clic droit sur dossier
    ↓
EXPLORER.EXE
    ↓
Demande : "Qui gère les menus contextuels ?"
    ↓
REGISTRE WINDOWS
    ↓
Répond : "7-Zip avec CLSID {23170F69-...}"
    ↓
WINDOWS cherche ce CLSID dans HKCR\CLSID\
    ↓
Trouve : "InProcServer32 = C:\Program Files\7-Zip\7-zip.dll"
    ↓
WINDOWS charge la DLL en mémoire
    ↓
Appelle la fonction COM : IContextMenu::QueryContextMenu()
    ↓
7-ZIP.DLL répond : "Mes options sont : Extraire ici, Compresser..."
    ↓
WINDOWS affiche le menu avec ces options
    ↓
TU cliques sur "Extraire ici"
    ↓
WINDOWS appelle : IContextMenu::InvokeCommand()
    ↓
7-ZIP.DLL exécute le code d'extraction
    ↓
Fichiers extraits ! ✅
```

***
