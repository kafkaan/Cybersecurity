# System Navigation

### <mark style="color:red;">System Navigation</mark>

***

### <mark style="color:blue;">1️⃣ Lister un répertoire :</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`dir`</mark>

#### <mark style="color:green;">📌 Commande</mark>

```cmd
dir
```

#### <mark style="color:green;">🧠 Rôle</mark>

Affiche le contenu du répertoire courant :

* fichiers
* dossiers
* taille
* dates
* espace disque disponible

#### <mark style="color:green;">📎 Exemple</mark>

```cmd
C:\Users\htb\Desktop> dir
```

#### 🔎 Informations affichées

* `.` → répertoire courant
* `..` → répertoire parent
* `<DIR>` → dossier
* taille des fichiers
* espace disque libre

#### 🛠️ Aide

```cmd
dir /?
```

➡️ Permet de découvrir les options avancées (filtres, tri, recherche).

***

### <mark style="color:blue;">2️⃣ Savoir où l’on se trouve :</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`cd`</mark> <mark style="color:blue;"></mark><mark style="color:blue;">/</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`chdir`</mark>

#### <mark style="color:green;">📌 Commande</mark>

```cmd
cd
```

#### <mark style="color:green;">🧠 Rôle</mark>

Affiche le **répertoire de travail actuel** (Current Working Directory).

#### <mark style="color:green;">📎 Exemple</mark>

```cmd
C:\htb> cd
C:\htb
```

🔐 Important :\
Tous les fichiers ou commandes sans chemin précisé s’exécutent **depuis ce répertoire**.

***

### <mark style="color:blue;">3️⃣ Se déplacer dans le système :</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`cd`</mark>

#### <mark style="color:green;">📌 Commande générale</mark>

```cmd
cd <chemin>
```

***

### <mark style="color:blue;">4️⃣ Comprendre la racine du système (Root)</mark>

#### <mark style="color:green;">📌 Racine Windows</mark>

```
C:\
```

📝 Historique :

* `A:\` et `B:\` → lecteurs disquettes
* `C:\` → disque principal

***

### <mark style="color:blue;">5️⃣ Chemins absolus vs relatifs</mark>

***

#### <mark style="color:green;">🔹 Chemin absolu</mark>

📌 Défini **depuis la racine (`C:\`)**

```cmd
cd C:\Users\htb\Pictures
```

➡️ Fonctionne **peu importe** le répertoire actuel.

***

#### <mark style="color:green;">🔹 Chemin relatif</mark>

📌 Défini **par rapport au répertoire courant**

```cmd
cd .\Pictures
```

🔎 Symboles importants :

| Symbole | Signification      |
| ------- | ------------------ |
| `.`     | répertoire courant |
| `..`    | répertoire parent  |

***

#### <mark style="color:green;">📎 Exemple combiné</mark>

Répertoire actuel :

```cmd
C:\Users\htb\Pictures>
```

Revenir à la racine :

```cmd
cd ..\..\..\
```

➡️ Remonte 3 niveaux d’un coup

***

### <mark style="color:blue;">6️⃣ Explorer l’arborescence :</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`tree`</mark>

#### 📌 <mark style="color:green;">Commande</mark>

```cmd
tree
```

#### 🧠 <mark style="color:green;">Rôle</mark>

Affiche la structure complète des dossiers sous forme d’arbre.

#### <mark style="color:green;">📎 Exemple</mark>

```cmd
C:\Users\htb> tree
```

***

#### <mark style="color:green;">🔹 Voir aussi les fichiers :</mark> <mark style="color:green;"></mark><mark style="color:green;">`/F`</mark>

```cmd
tree /F
```

➡️ Très utile pour :

* repérer rapidement des fichiers sensibles
* cartographier le système

⚠️ Peut générer **beaucoup de sortie**\
➡️ Utiliser `Ctrl + C` pour interrompre

***

### <mark style="color:blue;">7️⃣ Vision attaquant : répertoires intéressants</mark>

#### <mark style="color:green;">📌 Répertoires souvent abusés en cybersécurité</mark>

| Nom                   | Chemin                               | Intérêt                                            |
| --------------------- | ------------------------------------ | -------------------------------------------------- |
| `%SYSTEMROOT%\Temp`   | `C:\Windows\Temp`                    | Accessible à tous, idéal pour déposer des fichiers |
| `%TEMP%`              | `C:\Users\<user>\AppData\Local\Temp` | Fichiers temporaires utilisateur                   |
| `%PUBLIC%`            | `C:\Users\Public`                    | Peu surveillé, accès en écriture                   |
| `%ProgramFiles%`      | `C:\Program Files`                   | Applications installées (64-bit)                   |
| `%ProgramFiles(x86)%` | `C:\Program Files (x86)`             | Applications 32-bit                                |

🎯 Intérêt offensif :

* dépôt de payloads
* reconnaissance
* persistance
* contournement de surveillance

***

### <mark style="color:blue;">8️⃣ Résumé rapide (à mémoriser)</mark>

| Action                | Commande      |
| --------------------- | ------------- |
| Lister un dossier     | `dir`         |
| Connaître sa position | `cd`          |
| Se déplacer           | `cd <chemin>` |
| Racine Windows        | `C:\`         |
| Explorer arborescence | `tree`        |
| Arbre + fichiers      | `tree /F`     |

***
