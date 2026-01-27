# Unconditional Branching

***

## <mark style="color:red;">🔁</mark> <mark style="color:red;"></mark><mark style="color:red;">**Saut inconditionnel (Unconditional Branching)**</mark>

Le **deuxième type d’instructions de contrôle (Control Instructions)** est celui des **instructions de branchement (Branching Instructions)**, qui sont des instructions générales permettant de **sauter vers n’importe quel point du programme** **si une condition est remplie**.

Commençons par discuter de l’instruction de branchement la plus simple : `jmp`, qui **saute toujours vers un emplacement, sans condition**.

***

#### <mark style="color:green;">🧠</mark> <mark style="color:green;"></mark><mark style="color:green;">`jmp loopFib`</mark>

L’instruction `jmp` fait sauter le programme vers une **étiquette (label)** ou un emplacement précisé en **opérande**. Le programme **poursuivra son exécution à cet endroit**.

Une fois que l'exécution est redirigée ailleurs, le programme **continue à traiter les instructions depuis ce point**.

Si on souhaite **sauter temporairement à un point et revenir ensuite**, on utilisera des **fonctions**, que l’on verra dans la prochaine section.

***

⚠️ L’instruction `jmp` est **inconditionnelle**, c’est-à-dire qu’elle **sautera toujours** vers l’emplacement indiqué, **peu importe la situation**.

Cela la distingue des **sauts conditionnels**, qui ne sont effectués **que si une condition spécifique est vraie** (on les verra ensuite).

***

#### <mark style="color:green;">📘 Table récapitulative</mark>

<table data-full-width="true"><thead><tr><th>Instruction</th><th>Description</th><th>Exemple</th></tr></thead><tbody><tr><td><code>jmp</code></td><td>Saute vers un label, une adresse, ou un emplacement spécifique</td><td><code>jmp loop</code></td></tr></tbody></table>

***

### <mark style="color:green;">🧪 Test dans notre</mark> <mark style="color:green;"></mark><mark style="color:green;">`fib.s`</mark>

Testons l’utilisation de `jmp` dans notre fichier `fib.s` et voyons comment cela **modifie le flux d’exécution**.\
Au lieu de boucler avec `loop loopFib`, on va utiliser **`jmp loopFib`**.

***

#### 📜 Code NASM (inchangé, sauf `loop → jmp`)

```asm
global  _start

section .text
_start:
    xor rax, rax    ; initialise rax à 0
    xor rbx, rbx    ; initialise rbx à 0
    inc rbx         ; incrémente rbx à 1
    mov rcx, 10

loopFib:
    add rax, rbx    ; obtient le nombre suivant
    xchg rax, rbx   ; échange les valeurs
    jmp loopFib     ; saut inconditionnel
```

***

### <mark style="color:green;">🧪 Exécution dans GDB</mark>

On assemble et on exécute comme d’habitude :

```bash
$ ./assembler.sh fib.s -g
```

Puis dans GDB :

```gdb
gef➤  b loopFib
Breakpoint 1 at 0x40100e
gef➤  r
```

***

#### 🔍 Valeurs des registres pendant l’exécution :

```gdb
──────────────────────────────────────────────────────── registers ────
$rbx   : 0x1
$rcx   : 0xa
$rcx   : 0xa

──────────────────────────────────────────────────────── registers ────
$rax   : 0x1
$rbx   : 0x1
$rcx   : 0xa

──────────────────────────────────────────────────────── registers ────
$rax   : 0x1
$rbx   : 0x2
$rcx   : 0xa

──────────────────────────────────────────────────────── registers ────
$rax   : 0x2
$rbx   : 0x3
$rcx   : 0xa

──────────────────────────────────────────────────────── registers ────
$rax   : 0x3
$rbx   : 0x5
$rcx   : 0xa

──────────────────────────────────────────────────────── registers ────
$rax   : 0x5
$rbx   : 0x8
$rcx   : 0xa
```

***

🧠 On appuie sur `c` plusieurs fois pour laisser le programme sauter plusieurs fois vers `loopFib`.

Comme on le voit, le programme **calcule toujours correctement la suite de Fibonacci**.

***

<mark style="color:green;">⚠️</mark> <mark style="color:green;"></mark><mark style="color:green;">**Différence principale**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>\
Le registre `rcx` **ne se décrémente pas**.\
C’est parce que l’instruction `jmp` **ne tient pas compte** de `rcx` comme compteur, contrairement à `loop`.

***

### <mark style="color:blue;">🧹 Supprimer le breakpoint et observer</mark>

On supprime le point d’arrêt avec `del 1`, puis on laisse le programme tourner :

```asm
gef➤  info break
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x000000000040100e <loopFib>
	breakpoint already hit 6 times
gef➤  del 1
gef➤  c
Continuing.
```

***

#### <mark style="color:green;">💥 Le programme tourne à l’infini</mark>

```asm
Program received signal SIGINT, Interrupt.
0x000000000040100e in loopFib ()
──────────────────────────────────────────────────────── registers ────
$rax   : 0x2e02a93188557fa9
$rbx   : 0x903b4b15ce8cedf0
$rcx   : 0xa
```

On remarque que le programme a **continué à tourner** jusqu’à ce qu’on fasse `Ctrl + C` pour l’arrêter manuellement.\
À ce moment, le nombre de Fibonacci est énorme : `0x903b4b15ce8cedf0`.

***

📌 **Pourquoi ?**\
Parce que l’instruction `jmp` saute **indéfiniment** vers `loopFib`, **sans condition**, donc la boucle tourne **à l’infini**, comme un `while(true)`.

***

### <mark style="color:red;">❌ Pourquoi ne pas utiliser</mark> <mark style="color:red;"></mark><mark style="color:red;">`jmp`</mark> <mark style="color:red;"></mark><mark style="color:red;">pour une vraie boucle ?</mark>

* L’instruction `jmp` ne s’arrêtera **jamais** d’elle-même.
* `rcx` n’est **pas décrémenté automatiquement**, donc pas de sortie naturelle de boucle.
* Il faut un `cmp` + saut conditionnel pour sortir (→ **prochaine leçon**).

***

🧠 Conclusion : le `jmp` est utile pour :

* Sauts inconditionnels
* Boucles **infinies**
* Sauts vers du code spécifique, par exemple une routine personnalisée

***
