# Working with Directories & Files

## <mark style="color:red;">Working with Directories & Files</mark>

***

### <mark style="color:blue;">📁 1. Les dossiers (Directories)</mark>

#### 📌 Définition

Un **directory** est un dossier contenant :

* d’autres dossiers
* des fichiers

📂 Structure hiérarchique (ex : hôtel)

* `C:\` → racine
* `C:\Users\` → étage
* `C:\Users\htb\Desktop` → couloir
* `file.txt` → chambre

***

#### 📋 Lister les dossiers

| Commande  | Description               |
| --------- | ------------------------- |
| `dir`     | liste fichiers + dossiers |
| `tree`    | affiche l’arborescence    |
| `tree /F` | arborescence + fichiers   |

***

#### ➕ Créer un dossier

```cmd
md nom_du_dossier
mkdir nom_du_dossier
```

➡️ `md` et `mkdir` font **exactement la même chose**

***

#### ❌ Supprimer un dossier

| Commande        | Usage                      |
| --------------- | -------------------------- |
| `rd dossier`    | supprime un dossier vide   |
| `rd /S dossier` | supprime dossier + contenu |
| `rmdir`         | alias de `rd`              |

⚠️ Si le dossier n’est pas vide → **/S obligatoire**

***

#### 🔄 Déplacer / Copier des dossiers

**🔁 move**

```cmd
move source destination
```

* déplace dossier + contenu
* peut renommer

**📦 xcopy (ancien mais utile)**

```cmd
xcopy source destination /E
```

| Option | Rôle                                   |
| ------ | -------------------------------------- |
| `/E`   | inclut sous-dossiers (même vides)      |
| `/K`   | conserve attributs (read-only, hidden) |

➡️ **Intéressant en pentest** pour copier des fichiers verrouillés

***

#### 🚀 robocopy (avancé)

```cmd
robocopy source destination
```

💡 Capacités :

* conserve **ACL, timestamps, attributs**
* copie local / réseau
* gère gros volumes

⚠️ Option dangereuse :

```cmd
/MIR
```

➡️ **MIROIR** : supprime tout ce qui n’existe pas côté source

🧪 Mode test :

```cmd
/L
```

➡️ affiche ce qui se passerait **sans exécuter**

***

### <mark style="color:blue;">📄 2. Les fichiers (Files)</mark>

#### 📋 Lister les fichiers

```cmd
dir
tree /F
```

***

#### 👀 Lire le contenu d’un fichier

**🧾 type**

```cmd
type fichier.txt
```

* rapide
* ne verrouille pas le fichier

**📖 more**

```cmd
more fichier.txt
```

* lecture page par page
* utile pour gros fichiers

```cmd
commande | more
```

***

#### ✍️ Créer / modifier un fichier

**echo**

```cmd
echo texte > fichier.txt      (écrase)
echo texte >> fichier.txt     (ajoute)
```

**fsutil**

```cmd
fsutil file createNew fichier.txt 100
```

➡️ crée un fichier de taille définie

***

#### ✏️ Renommer un fichier

```cmd
ren ancien.txt nouveau.txt
rename ancien.txt nouveau.txt
```

***

### <mark style="color:blue;">🔁 3. Redirections & Pipes (I/O)</mark>

#### ➡️ Sortie vers fichier

```cmd
commande > fichier.txt
commande >> fichier.txt
```

#### ⬅️ Entrée depuis fichier

```cmd
commande < fichier.txt
```

#### 🔗 Pipe

```cmd
commande1 | commande2
```

Ex :

```cmd
ipconfig /all | find "IPv4"
```

***

#### ⛓️ Enchaîner des commandes

| Symbole | Signification              |
| ------- | -------------------------- |
| `&`     | exécute A puis B           |
| `&&`    | exécute B **si A réussit** |
| \`      |                            |

***

### <mark style="color:blue;">🗑️ 4. Supprimer des fichiers</mark>

#### ❌ del / erase

```cmd
del fichier.txt
erase fichier.txt
```

#### 🧹 Supprimer par attribut

| Attribut | Signification |
| -------- | ------------- |
| `R`      | Read-only     |
| `H`      | Hidden        |
| `S`      | System        |

```cmd
dir /A:H        (voir fichiers cachés)
del /A:H *      (supprimer fichiers cachés)
del /A:R *      (supprimer read-only)
```

⚠️ Confirmation requise sauf `/Q`

***

### <mark style="color:blue;">📦 5. Copier / déplacer des fichiers</mark>

#### 📋 copy

```cmd
copy source destination
```

Option :

```cmd
/V   (vérification après copie)
```

#### 🚚 move

```cmd
move source destination
```

* déplace
* renomme
* fonctionne aussi pour dossiers

***

### <mark style="color:blue;">🧠 6. Point de vue sécurité / pentest</mark>

📌 Intéressant pour un attaquant :

* `Desktop`, `Documents`, `Downloads`
* fichiers `.txt`, `.ps1`, `.config`
* `xcopy` / `robocopy` pour exfiltration discrète
* `type` / `more` pour lire sans alerter
* fichiers cachés (`/A:H`)

📌 Intéressant pour un défenseur :

* conserver attributs (robocopy)
* analyser fichiers suspects
* surveiller copies massives

***

### ✅ À retenir (ultra résumé)

* `dir`, `tree` → voir
* `md`, `rd` → créer / supprimer dossiers
* `copy`, `move`, `xcopy`, `robocopy` → manipuler
* `type`, `more` → lire fichiers
* `> >> < | && ||` → automatiser & chaîner

***
