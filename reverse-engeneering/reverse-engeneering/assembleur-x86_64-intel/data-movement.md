# Data Movement

***

#### <mark style="color:green;">**Déplacement de données**</mark>

Commencez avec les instructions de déplacement de données, qui sont parmi les instructions les plus fondamentales dans tout programme assembleur.

* Nous utiliserons fréquemment ces instructions pour déplacer des données entre adresses, déplacer des données entre registres et adresses mémoire, et charger des données immédiates dans des registres ou adresses mémoire.\

* Les principales instructions de **déplacement de données** sont :

<table data-full-width="true"><thead><tr><th>Instruction</th><th>Description</th><th>Exemple</th></tr></thead><tbody><tr><td><mark style="color:red;"><strong><code>mov</code></strong></mark></td><td>Déplacer des données ou charger des données immédiates</td><td><code>mov rax, 1</code> → <code>rax = 1</code></td></tr><tr><td><mark style="color:red;"><strong><code>lea</code></strong></mark></td><td>Charger une adresse pointant vers la valeur</td><td><code>lea rax, [rsp+5]</code> → <code>rax = rsp + 5</code></td></tr><tr><td><mark style="color:red;"><strong><code>xchg</code></strong></mark></td><td>Échanger des données entre deux registres ou adresses</td><td><code>xchg rax, rbx</code> → <code>rax = rbx, rbx = rax</code></td></tr></tbody></table>

***

#### <mark style="color:green;">**Déplacement de données**</mark>

Utilisons `mov` comme première instruction dans notre projet Fibonacci.\
Il faut charger les valeurs initiales F0 = 0 et F1 = 1 dans `rax` et `rbx` respectivement.

Code à copier dans `fib.s` :

```nasm
global  _start

section .text
_start:
    mov rax, 0
    mov rbx, 1
```

Assemblons et exécutons avec `gdb` pour voir `mov` en action :

{% code fullWidth="true" %}
```
$ ./assembler.sh fib.s -g
gef➤  b _start
Breakpoint 1 at 0x401000
gef➤  r
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x401000 <_start+0>       mov    eax, 0x0
     0x401005 <_start+5>       mov    ebx, 0x1
───────────────────────────────────────────────────────────────────────────────────── registres ────
$rax   : 0x0
$rbx   : 0x0

...SNIP...

─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401000 <_start+0>       mov    eax, 0x0
 →   0x401005 <_start+5>       mov    ebx, 0x1
───────────────────────────────────────────────────────────────────────────────────── registres ────
$rax   : 0x0
$rbx   : 0x1
```
{% endcode %}

Ainsi, nous avons chargé les valeurs initiales dans les registres pour d’autres opérations.

**Remarque :** en assembleur, déplacer des données ne modifie pas la source. `mov` est plutôt une **copie**, pas un déplacement.

***

#### <mark style="color:green;">**Chargement de données**</mark>

On peut charger une constante immédiate avec `mov`, par exemple `mov rax, 1`.\
La taille de la donnée chargée dépend du registre : ici, le registre 64 bits `rax` charge une valeur 64 bits (0x0000000000000001), ce qui n’est pas optimal.

Il est plus efficace d’utiliser un registre adapté à la taille de la donnée, comme `al` (1 octet).\
Exemple : `mov al, 1` charge 0x01, ce qui est plus compact.

Comparaison avec `objdump` :

```nasm
global  _start

section .text
_start:
    mov rax, 0
    mov rbx, 1
    mov bl, 1
```

```
$ nasm -f elf64 fib.s && objdump -M intel -d fib.o
0000000000000000 <_start>:
   0:    b8 00 00 00 00        mov    eax,0x0
   5:    bb 01 00 00 00        mov    ebx,0x1
   a:    b3 01                 mov    bl,0x1
```

La première instruction prend plus du double de l’espace comparée à la dernière.

***

#### <mark style="color:green;">**Version sous‑registres**</mark>

Code optimisé :

```nasm
global  _start

section .text
_start:
    mov al, 0
    mov bl, 1
```

***

#### <mark style="color:green;">**Instruction**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`xchg`**</mark>

`xchg` échange les données entre deux registres.\
Ajoutez `xchg rax, rbx` à la fin, assemblez et lancez avec `gdb` pour voir le résultat.

***

#### <mark style="color:green;">**Pointeurs d’adresses**</mark>

Un registre peut contenir une **adresse** pointant vers une autre valeur.\
C’est typiquement le cas avec `rsp`, `rbp`, `rip`, etc.

Exemple avec `gdb` sur `fib` :

```gdb
gdb -q ./fib
gef➤  b _start
Breakpoint 1 at 0x401000
gef➤  r
...SNIP...
$rsp   : 0x00007fffffffe490  →  0x0000000000000001
$rip   : 0x0000000000401000  →  <_start+0> mov eax, 0x0
```

***

#### <mark style="color:green;">**Déplacement des valeurs pointées**</mark>

* `mov rax, rsp` charge **l’adresse** de `rsp`, pas la valeur.
* Pour charger la **valeur** pointée, utilisez `[]` : `mov rax, [rsp]`.
* On peut aussi utiliser un offset : `mov rax, [rsp+10]`.

Exemple :

```nasm
global  _start

section .text
_start:
    mov rax, rsp
    mov rax, [rsp]
```

Avec `gdb` on observe :

```
 → mov rax, rsp
$rax = 0x00007fffffffe490  → 0x1
…
 → mov rax, QWORD PTR [rsp]
$rax = 0x1
```

***

**Remarque :** `nasm` infère souvent la taille (ex. `QWORD PTR`), mais on peut préciser `byte`, `qword`, etc.

***

#### <mark style="color:green;">**Chargement d’une adresse effective (**</mark><mark style="color:green;">**`lea`**</mark><mark style="color:green;">**)**</mark>

`lea rax, [rsp]` charge **l’adresse** (opposé de `mov rax, [rsp]`).

Utile pour manipuler des données trop volumineuses pour un registre, notamment pour les appels systèmes (ex. `write`).

* `mov rax, rsp` ou `lea rax, [rsp]` stockent l’adresse.
* `lea` est indispensable pour charger une adresse avec offset : `lea rax, [rsp+10]`.
* `mov rax, [rsp+10]` chargerait la **valeur** à cette adresse, pas l’adresse.

***

**Exemple :**

```nasm
global  _start

section .text
_start:
    lea rax, [rsp+10]
    mov rax, [rsp+10]
```

**Gdb :**

```
 → lea rax, [rsp+0xa]
$rax = 0x00007fffffffe49a
…
 → mov rax, QWORD PTR [rsp+0xa]
$rax = 0x7fffffff
```

***

#### <mark style="color:green;">**Résumé des différences**</mark>

* `mov rax, [rsp]` → **valeur** pointée
* `mov rax, rsp` → **adresse** elle-même
* `lea rax, [rsp+10]` → **adresse + offset**
* `mov rax, [rsp+10]` → **valeur à l’adresse + offset**

***
