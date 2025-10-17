# Instructions arithmétiques

### <mark style="color:red;">🧮 Instructions arithmétiques</mark>

Le **deuxième type d'instructions de base** est constitué des **instructions arithmétiques**.\
Avec ces instructions, on peut effectuer **divers calculs mathématiques** sur les données stockées dans les registres et les adresses mémoire.\
Ces instructions sont en général traitées par l’**ALU** (Arithmetic Logic Unit) du CPU, parmi d’autres.

Nous allons séparer les instructions arithmétiques en deux types :

* Celles qui prennent **un seul opérande** (Unaires)
* Celles qui prennent **deux opérandes** (Binaires)

***

#### <mark style="color:green;">✅ Instructions unaires</mark>

Voici les principales **instructions arithmétiques unaires** (on suppose que `rax` commence avec la valeur `1` pour chaque instruction) :

<table data-full-width="true"><thead><tr><th>Instruction</th><th>Description</th><th>Exemple</th></tr></thead><tbody><tr><td><code>inc</code></td><td>Incrémente de 1</td><td><code>inc rax</code> → <code>rax++</code> ou <code>rax += 1</code> → <code>rax = 2</code></td></tr><tr><td><code>dec</code></td><td>Décrémente de 1</td><td><code>dec rax</code> → <code>rax--</code> ou <code>rax -= 1</code> → <code>rax = 0</code></td></tr></tbody></table>

***

#### <mark style="color:green;">🔁 Exercice avec</mark> <mark style="color:green;"></mark><mark style="color:green;">`fib.s`</mark>

On a initialisé `rax` et `rbx` avec `0` et `1` avec l’instruction `mov`.\
Ici, on va plutôt **mettre 0 dans `bl`**, puis **utiliser `inc` pour obtenir 1** :

**📜 Code NASM :**

```nasm
global  _start
section .text
_start:
    mov al, 0
    mov bl, 0
    inc bl
```

***

<mark style="color:green;">**Ensuite, on assemble et on exécute avec gdb :**</mark>

```bash
$ ./assembler.sh fib.s -g
...SNIP...

──────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x401005 <_start+5>      mov    al, 0x0
───────────────────────────────────────────────────────────────── registers ────
$rbx   : 0x0

...SNIP...

──────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x40100a <_start+10>      inc    bl
───────────────────────────────────────────────────────────────── registers ────
$rbx   : 0x1
```

🧠 Comme on le voit, `rbx` valait 0, et après `inc bl`, il est passé à 1.\
L’instruction `dec` fonctionne pareil, mais **décrémente** au lieu d’incrémenter.

***

#### <mark style="color:green;">🧮 Instructions binaires</mark>

Maintenant, les **instructions arithmétiques binaires**. Voici les principales (on suppose que `rax` et `rbx` valent `1`) :

<table data-full-width="true"><thead><tr><th>Instruction</th><th>Description</th><th>Exemple</th></tr></thead><tbody><tr><td><code>add</code></td><td>Additionne les deux opérandes</td><td><code>add rax, rbx</code> → <code>rax = 1 + 1 = 2</code></td></tr><tr><td><code>sub</code></td><td>Soustrait la source de la destination</td><td><code>sub rax, rbx</code> → <code>rax = 1 - 1 = 0</code></td></tr><tr><td><code>imul</code></td><td>Multiplie les deux opérandes</td><td><code>imul rax, rbx</code> → <code>rax = 1 * 1 = 1</code></td></tr></tbody></table>

**Remarque :** le résultat est toujours stocké dans **l’opérande destination**, et **la source n’est pas modifiée**.

***

#### ➕ Exercice avec `add`

L’addition est **la base** de la suite de Fibonacci : `Fn = Fn-1 + Fn-2`.

On ajoute `add rax, rbx` à la fin du fichier `fib.s` :

**📜 Code NASM :**

```nasm
global  _start

section .text
_start:
   mov al, 0
   mov bl, 0
   inc bl
   add rax, rbx
```

***

#### <mark style="color:green;">🧪 Exécution dans gdb :</mark>

```bash
gdb
$ ./assembler.sh fib.s -g
gef➤  b _start
Breakpoint 1 at 0x401000
gef➤  r
...SNIP...

──────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401004 <_start+4>       inc    bl
 →   0x401006 <_start+6>       add    rax, rbx
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1
$rbx   : 0x1
```

🧠 Résultat : `rax = 0x1 + 0x0 = 0x1`.\
Si `rax` et `rbx` avaient d'autres valeurs Fibonacci, on aurait obtenu le suivant avec `add`.

Tu peux aussi tester `sub` et `imul` comme dans le tableau.

***

### <mark style="color:red;">🧠 Instructions bit-à-bit (Bitwise)</mark>

Ces instructions travaillent **au niveau des bits**.\
On suppose ici que `rax = 1` et `rbx = 2`.

<table data-full-width="true"><thead><tr><th>Instruction</th><th>Description</th><th>Exemple</th></tr></thead><tbody><tr><td><code>not</code></td><td>Inverse tous les bits (<code>0 → 1</code>, <code>1 → 0</code>)</td><td><code>not rax</code> → <code>NOT 00000001 = 11111110</code></td></tr><tr><td><code>and</code></td><td><code>1</code> uniquement si les deux bits sont à <code>1</code></td><td><code>and rax, rbx</code> → <code>00000001 AND 00000010 = 00000000</code></td></tr><tr><td><code>or</code></td><td><code>1</code> si l’un des deux bits est à <code>1</code></td><td><code>or rax, rbx</code> → <code>00000001 OR 00000010 = 00000011</code></td></tr><tr><td><code>xor</code></td><td><code>1</code> si les bits sont différents</td><td><code>xor rax, rbx</code> → <code>00000001 XOR 00000010 = 00000011</code></td></tr></tbody></table>

***

🔧 Ces instructions opèrent **bit par bit** sur les registres.

* `not` → inverse chaque bit
* `and` → compare chaque bit et retourne `1` si les deux sont `1`
* `or` → retourne `1` si au moins un bit est à `1`
* `xor` → retourne `1` si les bits sont différents

{% hint style="info" %}
#### <mark style="color:green;">🚀 Utilité de</mark> <mark style="color:green;"></mark><mark style="color:green;">`xor`</mark>

Très utile pour **mettre à 0 un registre** ! `xor rax, rax` → `rax = 0`, car tous les bits sont identiques, donc XOR les annule.
{% endhint %}

***

#### <mark style="color:green;">📜 Version optimisée de fib.s avec</mark> <mark style="color:green;"></mark><mark style="color:green;">`xor`</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

```nasm
global  _start

section .text
_start:
    xor rax, rax
    xor rbx, rbx
    inc rbx
    add rax, rbx
```

***

#### <mark style="color:green;">🧪 Exécution dans gdb :</mark>

```bash
gdb
$ ./assembler.sh fib.s -g
gef➤  b _start
Breakpoint 1 at 0x401000
gef➤  r
...SNIP...

──────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x401001 <_start+1>       xor    eax, eax
     0x401003 <_start+3>       xor    ebx, ebx
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x0

...SNIP...

──────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x40100c                  add    BYTE PTR [rax], al
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1
$rbx   : 0x1
```

🧠 Ici, `rax` et `rbx` sont mis à `0` via `xor`, ensuite `rbx` est incrémenté, et on ajoute `rax` + `rbx`.

***
