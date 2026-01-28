# Using the Stack

***

## <mark style="color:red;">💾 Utilisation de la pile (Using the Stack)</mark>

***

### <mark style="color:blue;">📌 Introduction</mark>

Dans la section sur l’architecture des ordinateurs, nous avons vu que la RAM est **segmentée** en **quatre zones principales**, et que chaque application reçoit sa propre **mémoire virtuelle** avec ses segments.\
Nous avons également vu le **segment texte** (où les instructions assembleur de l’application sont chargées), et le **segment de données** (où les variables sont stockées).

Maintenant, commençons à parler de la **pile (stack)**.

***

### <mark style="color:blue;">📦 La pile (The Stack)</mark>

La pile est une **zone mémoire réservée** pour qu’un programme puisse y **stocker des données temporairement**.

* Le **haut de la pile** est indiqué par le **registre RSP** _(Top Stack Pointer)_. :arrow\_up:
* Le **bas de la pile** est indiqué par le **registre RBP** _(Base Stack Pointer)_. :arrow\_down:

On peut **pousser des données (push)** dans la pile, ce qui place la donnée au sommet de la pile (valeur de RSP),\
et on peut **retirer des données (pop)** de la pile pour les mettre dans un registre ou une adresse mémoire.\
La donnée est alors **retirée du sommet**.

***

#### <mark style="color:green;">📚 Instructions :</mark>

| Instruction | Description                                             | Exemple    |
| ----------- | ------------------------------------------------------- | ---------- |
| `push`      | Copie un registre/adresse vers le sommet de la pile     | `push rax` |
| `pop`       | Déplace l’élément du sommet de la pile vers un registre | `pop rax`  |

> La pile est organisée en **LIFO** (Last In, First Out) → le **dernier** élément poussé est le **premier** à sortir.

Par exemple :

* si tu fais `push rax`, la valeur de `rax` est maintenant tout en haut de la pile.
* si tu fais ensuite `push rbx`, il faut **retirer rbx d’abord** avant de pouvoir accéder à rax à nouveau.

***

#### 🧠 Exemple visuel :

```
0xabcdef        <-- Sommet de la pile ($rsp)
0x1234567890    <-- Bas de la pile ($rbp)
```

Registre :

```
rax: 
```

Tu peux cliquer sur `push` pour empiler la valeur de `rax`,\
ou `pop` pour retirer la valeur en haut de la pile dans `rax`.

***

### <mark style="color:red;">🧰 Utilisation avec les fonctions ou les appels système (syscalls)</mark>

En général, **avant d’appeler une fonction ou une syscall**, on **pousse les registres importants** sur la pile,puis **on les restaure** après l’appel.\
Pourquoi ?\
→ Parce que les fonctions ou les syscalls utilisent ces registres et peuvent en modifier le contenu.

***

#### <mark style="color:green;">✅ Exemple :</mark>

Si on veut faire une syscall pour afficher `Hello World` sans perdre la valeur contenue dans `rax`,\
on fait :

```asm
push rax         ; sauvegarde
; exécuter syscall
pop rax          ; restauration
```

Ainsi, on peut **exécuter la syscall** ET **garder intact la valeur originale de `rax`**.

***

### <mark style="color:green;">✍️ PUSH / POP en contexte réel</mark>

Code assembleur :

```asm
global  _start

section .text
_start:
    xor rax, rax    ; rax = 0
    xor rbx, rbx    ; rbx = 0
    inc rbx         ; rbx = 1
loopFib:
    add rax, rbx    ; rax = rax + rbx
    xchg rax, rbx   ; échange rax <=> rbx
    cmp rbx, 10     ; comparer rbx à 10
    js loopFib      ; sauter si rbx < 10
```

***

Imaginons qu'on veut **appeler une fonction ou une syscall avant d'entrer dans la boucle**.

➡️ On **sauvegarde `rax` et `rbx` sur la pile** avant, puis **on les restaure après** :

```nasm
global  _start

section .text
_start:
    xor rax, rax
    xor rbx, rbx
    inc rbx
    push rax        ; empile rax
    push rbx        ; empile rbx
    ; appel de fonction ici
    pop rbx         ; restaure rbx
    pop rax         ; restaure rax
    ; suite du programme...
```

> **Attention** : les `pop` doivent être faits dans **l’ordre inverse** des `push`.

***

### <mark style="color:green;">🔍 Analyse avec GDB</mark>

Commande :

```bash
./assembler.sh fib.s -g
```

Dans GDB :

```gdb
b _start
r
si
si
si
```

Tu observeras dans la pile :

```asm
$rax = 0x0
$rbx = 0x1
```

Et dans la pile :

```asm
0x00007fffffffe410│+0x0000: 0x0000000000000001  ← $rsp (valeur de rbx)
0x00007fffffffe418│+0x0008: 0x0000000000000000  (valeur de rax)
```

On voit bien que :

* **Le dernier élément poussé (rbx = 1)** est au sommet.
* **L’élément en-dessous (rax = 0)** est juste en dessous.

➡️ **Push = copie**, donc la valeur reste aussi dans les registres.

***

### <mark style="color:red;">📤 Restauration avec POP</mark>

Après un appel de fonction :

```asm
pop rbx
pop rax
```

→ Les valeurs sont **retirées de la pile** et **remises dans leurs registres d’origine**.

***

### <mark style="color:red;">🧠 Points clés à retenir</mark>

* La **pile fonctionne en LIFO**.
* Toujours **sauvegarder les registres modifiés par les fonctions/syscalls**.
* Toujours faire les `pop` dans **l’ordre inverse** des `push`.
* `push` **ne modifie pas** le registre source, c’est une **copie**.
* `pop` **retire** la valeur du sommet de la pile.

***
