# GDB CHEATSHEET

***

### <mark style="color:red;">📍 1.</mark> <mark style="color:red;"></mark><mark style="color:red;">`BREAK`</mark> <mark style="color:red;"></mark><mark style="color:red;">– Poser des points d’arrêt</mark>

#### 🎯 But :

Arrêter l’exécution à un endroit **précis** du programme pour :

* Inspecter l’état du programme
* Lire les **registres**
* Examiner la **pile**
* Exécuter le code instruction par instruction

#### <mark style="color:green;">✅ Commandes utiles :</mark>

<table data-full-width="true"><thead><tr><th>Commande</th><th>Description</th></tr></thead><tbody><tr><td><code>b &#x3C;fonction></code></td><td>Pose un breakpoint sur une fonction (<code>b _start</code>)</td></tr><tr><td><code>b *&#x3C;adresse></code></td><td>Pose un breakpoint sur une adresse précise</td></tr><tr><td><code>info breakpoints</code></td><td>Affiche tous les breakpoints</td></tr><tr><td><code>disable &#x3C;num></code> / <code>enable</code></td><td>Désactive / réactive un breakpoint</td></tr><tr><td><code>delete &#x3C;num></code></td><td>Supprime un breakpoint</td></tr><tr><td><code>c</code> ou <code>continue</code></td><td>Reprend l'exécution jusqu'au prochain point d’arrêt</td></tr><tr><td><code>r</code> ou <code>run</code></td><td>Lance le programme depuis le début</td></tr></tbody></table>

***

### <mark style="color:red;">🔍 2.</mark> <mark style="color:red;"></mark><mark style="color:red;">`EXAMINE`</mark> <mark style="color:red;"></mark><mark style="color:red;">– Examiner la mémoire, registres et instructions</mark>

#### <mark style="color:green;">🎯 But :</mark>

Lire le contenu :

* des registres
* de la pile
* de la mémoire (adresses précises)
* ou des instructions

#### <mark style="color:green;">✅ Commande principale :</mark> <mark style="color:green;"></mark><mark style="color:green;">`x/FMT ADRESSE`</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td>Format <code>FMT</code></td><td>Description</td></tr><tr><td><code>x</code></td><td>en hex</td></tr><tr><td><code>s</code></td><td>en string</td></tr><tr><td><code>i</code></td><td>instructions (ASM)</td></tr><tr><td><code>d</code></td><td>en décimal</td></tr><tr><td><code>b</code>, <code>h</code>, <code>w</code>, <code>g</code></td><td>taille : byte, 2B, 4B (word), 8B (quad)</td></tr><tr><td>Exemple : <code>x/4ig $rip</code></td><td>Affiche 4 instructions à partir de <code>$rip</code></td></tr></tbody></table>

#### <mark style="color:green;">✅ Autres commandes utiles :</mark>

<table data-full-width="true"><thead><tr><th>Commande</th><th>Description</th></tr></thead><tbody><tr><td><code>x/s &#x3C;adresse></code></td><td>Affiche la chaîne à l’adresse donnée</td></tr><tr><td><code>x/wx &#x3C;adresse></code></td><td>Affiche le mot mémoire (4B) en hex</td></tr><tr><td><code>x/4xg $rsp</code></td><td>Affiche 4 quadwords à partir de la pile</td></tr><tr><td><code>registers</code></td><td>Affiche tous les registres (GEF)</td></tr></tbody></table>

***

### <mark style="color:red;">👣 3.</mark> <mark style="color:red;"></mark><mark style="color:red;">`STEP`</mark> <mark style="color:red;"></mark><mark style="color:red;">– Avancer dans le programme, instruction par instruction</mark>

#### <mark style="color:green;">🎯 But :</mark>

Exécuter le programme :

* **une instruction à la fois** (`si`)
* ou **jusqu’à la prochaine ligne / retour fonction** (`s`, `ni`, `n`)

#### <mark style="color:green;">✅ Commandes utiles :</mark>

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

#### <mark style="color:green;">🎯 But :</mark>

Changer des **valeurs à la volée** :

* Modifie un registre (`set`)
* Écrase une adresse mémoire (`patch`)

***

#### <mark style="color:green;">✅ Modifier un registre :</mark>

```bash
gef➤ set $rdx = 0x9
```

* Change la valeur de `rdx` (par exemple pour changer la taille d’un `write()`)

***

#### <mark style="color:green;">✅ Modifier une adresse mémoire avec GEF (</mark><mark style="color:green;">`patch`</mark><mark style="color:green;">) :</mark>

```bash
gef➤ patch string 0x402000 "Patched!\\x0a"
```

* Remplace la string `"Hello HTB Academy!"` en `"Patched!\n"`

#### <mark style="color:green;">📌 Syntaxe :</mark>

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

#### <mark style="color:green;">🔥 Astuce bonus :</mark>

*   Tu peux taper `help <commande>` dans GDB pour voir sa doc rapide !\
    Exemple :

    ```bash
    gef➤ help patch
    gef➤ help x
    ```

***
