# Working with Directories & Files

## <mark style="color:red;">Working with Directories & Files</mark>

***

### <mark style="color:blue;">📁 1. Les dossiers (Directories)</mark>

#### <mark style="color:$success;">📌 Définition</mark>

Un **directory** est un dossier contenant :

* d’autres dossiers
* des fichiers

📂 Structure hiérarchique (ex : hôtel)

* `C:\` → racine
* `C:\Users\` → étage
* `C:\Users\htb\Desktop` → couloir
* `file.txt` → chambre

***

#### <mark style="color:green;">📋 Lister les dossiers</mark>

| Commande  | Description               |
| --------- | ------------------------- |
| `dir`     | liste fichiers + dossiers |
| `tree`    | affiche l’arborescence    |
| `tree /F` | arborescence + fichiers   |

***

#### <mark style="color:green;">➕ Créer un dossier</mark>

```cmd
md nom_du_dossier
mkdir nom_du_dossier
```

➡️ `md` et `mkdir` font **exactement la même chose**

***

#### <mark style="color:green;">❌ Supprimer un dossier</mark>

| Commande        | Usage                      |
| --------------- | -------------------------- |
| `rd dossier`    | supprime un dossier vide   |
| `rd /S dossier` | supprime dossier + contenu |
| `rmdir`         | alias de `rd`              |

⚠️ Si le dossier n’est pas vide → **/S obligatoire**

***

#### <mark style="color:green;">🔄 Déplacer / Copier des dossiers</mark>

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

#### <mark style="color:green;">🚀 robocopy (avancé)</mark>

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

#### <mark style="color:green;">📋 Lister les fichiers</mark>

```cmd
dir
tree /F
```

***

#### <mark style="color:green;">👀 Lire le contenu d’un fichier</mark>

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

#### <mark style="color:green;">✍️ Créer / modifier un fichier</mark>

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

#### <mark style="color:green;">➡️ Sortie vers fichier</mark>

```cmd
commande > fichier.txt
commande >> fichier.txt
```

#### <mark style="color:green;">⬅️ Entrée depuis fichier</mark>

```cmd
commande < fichier.txt
```

#### <mark style="color:green;">🔗 Pipe</mark>

```cmd
commande1 | commande2
```

Ex :

```cmd
ipconfig /all | find "IPv4"
```

***

#### <mark style="color:green;">⛓️ Enchaîner des commandes</mark>

| Symbole | Signification              |
| ------- | -------------------------- |
| `&`     | exécute A puis B           |
| `&&`    | exécute B **si A réussit** |
| \`      |                            |

***

### <mark style="color:blue;">🗑️ 4. Supprimer des fichiers</mark>

#### <mark style="color:green;">❌ del / erase</mark>

```cmd
del fichier.txt
erase fichier.txt
```

#### <mark style="color:green;">🧹 Supprimer par attribut</mark>

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

#### <mark style="color:green;">📋 copy</mark>

```cmd
copy source destination
```

Option :

```cmd
/V   (vérification après copie)
```

#### <mark style="color:green;">🚚 move</mark>

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

### <mark style="color:blue;">✅ À retenir</mark>&#x20;

* `dir`, `tree` → voir
* `md`, `rd` → créer / supprimer dossiers
* `copy`, `move`, `xcopy`, `robocopy` → manipuler
* `type`, `more` → lire fichiers
* `> >> < | && ||` → automatiser & chaîner

***
