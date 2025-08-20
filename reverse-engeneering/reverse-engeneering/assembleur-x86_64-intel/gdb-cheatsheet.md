# GDB CHEATSHEET

***

### <mark style="color:red;">📍 1.</mark> <mark style="color:red;"></mark><mark style="color:red;">`BREAK`</mark> <mark style="color:red;"></mark><mark style="color:red;">– Poser des points d’arrêt</mark>

#### 🎯 But :

Arrêter l’exécution à un endroit **précis** du programme pour :

* Inspecter l’état du programme
* Lire les **registres**
* Examiner la **pile**
* Exécuter le code instruction par instruction

#### ✅ Commandes utiles :

| Commande                   | Description                                         |
| -------------------------- | --------------------------------------------------- |
| `b <fonction>`             | Pose un breakpoint sur une fonction (`b _start`)    |
| `b *<adresse>`             | Pose un breakpoint sur une adresse précise          |
| `info breakpoints`         | Affiche tous les breakpoints                        |
| `disable <num>` / `enable` | Désactive / réactive un breakpoint                  |
| `delete <num>`             | Supprime un breakpoint                              |
| `c` ou `continue`          | Reprend l'exécution jusqu'au prochain point d’arrêt |
| `r` ou `run`               | Lance le programme depuis le début                  |

***

### <mark style="color:red;">🔍 2.</mark> <mark style="color:red;"></mark><mark style="color:red;">`EXAMINE`</mark> <mark style="color:red;"></mark><mark style="color:red;">– Examiner la mémoire, registres et instructions</mark>

#### 🎯 But :

Lire le contenu :

* des registres
* de la pile
* de la mémoire (adresses précises)
* ou des instructions

#### ✅ Commande principale : `x/FMT ADRESSE`

| Format `FMT`           | Description                               |
| ---------------------- | ----------------------------------------- |
| `x`                    | en hex                                    |
| `s`                    | en string                                 |
| `i`                    | instructions (ASM)                        |
| `d`                    | en décimal                                |
| `b`, `h`, `w`, `g`     | taille : byte, 2B, 4B (word), 8B (quad)   |
| Exemple : `x/4ig $rip` | Affiche 4 instructions à partir de `$rip` |

#### ✅ Autres commandes utiles :

| Commande         | Description                             |
| ---------------- | --------------------------------------- |
| `x/s <adresse>`  | Affiche la chaîne à l’adresse donnée    |
| `x/wx <adresse>` | Affiche le mot mémoire (4B) en hex      |
| `x/4xg $rsp`     | Affiche 4 quadwords à partir de la pile |
| `registers`      | Affiche tous les registres (GEF)        |

***

### <mark style="color:red;">👣 3.</mark> <mark style="color:red;"></mark><mark style="color:red;">`STEP`</mark> <mark style="color:red;"></mark><mark style="color:red;">– Avancer dans le programme, instruction par instruction</mark>

#### 🎯 But :

Exécuter le programme :

* **une instruction à la fois** (`si`)
* ou **jusqu’à la prochaine ligne / retour fonction** (`s`, `ni`, `n`)

#### ✅ Commandes utiles :

| Commande     | Description                                                  |
| ------------ | ------------------------------------------------------------ |
| `si`         | Step **instruction** (entre dans les appels)                 |
| `ni`         | Step instruction, mais **ne rentre pas dans les fonctions**  |
| `s`          | Step à la **prochaine ligne de code** ou **fin de fonction** |
| `n`          | Comme `s`, mais ne rentre pas dans les fonctions             |
| `si N`       | Avance de N instructions d’un coup                           |
| (Enter vide) | Répète la **dernière commande**                              |

#### Exemple :

```bash
gef➤  si
# Exécute l'instruction à $rip
```

***

### <mark style="color:red;">✏️ 4.</mark> <mark style="color:red;"></mark><mark style="color:red;">`MODIFY`</mark> <mark style="color:red;"></mark><mark style="color:red;">– Modifier la mémoire ou les registres</mark>

#### 🎯 But :

Changer des **valeurs à la volée** :

* Modifie un registre (`set`)
* Écrase une adresse mémoire (`patch`)

***

#### ✅ Modifier un registre :

```bash
gef➤ set $rdx = 0x9
```

* Change la valeur de `rdx` (par exemple pour changer la taille d’un `write()`)

***

#### ✅ Modifier une adresse mémoire avec GEF (`patch`) :

```bash
gef➤ patch string 0x402000 "Patched!\\x0a"
```

* Remplace la string `"Hello HTB Academy!"` en `"Patched!\n"`

#### 📌 Syntaxe :

```bash
patch (qword|dword|word|byte) ADRESSE VALEUR
```

***

### <mark style="color:red;">🛠️ Résumé rapide des commandes essentielles</mark>

| Catégorie   | Commande            | Description                                    |
| ----------- | ------------------- | ---------------------------------------------- |
| **Break**   | `b _start`          | Break à la fonction `_start`                   |
|             | `b *0x40100a`       | Break à une **adresse mémoire précise**        |
|             | `info breakpoints`  | Liste tous les breakpoints                     |
|             | `c` / `continue`    | Reprend l’exécution                            |
|             | `r` / `run`         | Lance depuis le début                          |
| **Examine** | `x/4i $rip`         | Affiche 4 instructions à partir de `$rip`      |
|             | `x/s 0x402000`      | Affiche la chaîne située à cette adresse       |
|             | `x/wx 0x401000`     | Affiche le mot mémoire en hex (opcode)         |
|             | `registers`         | Liste tous les registres (GEF)                 |
| **Step**    | `si` / `stepi`      | Exécute une instruction assembleur             |
|             | `s` / `step`        | Exécute une ligne complète (entre dans appels) |
|             | `ni` / `n`          | Ignore les appels de fonction                  |
| **Modify**  | `set $rdx = 0x9`    | Modifie la valeur du registre `rdx`            |
|             | `patch string addr` | Patch une string en RAM                        |

***

#### 🔥 Astuce bonus :

*   Tu peux taper `help <commande>` dans GDB pour voir sa doc rapide !\
    Exemple :

    ```bash
    gef➤ help patch
    gef➤ help x
    ```

***
