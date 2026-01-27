# GNU Debugger (GDB)

***

### <mark style="color:blue;">🐞</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Le débogage : une compétence essentielle**</mark>

Le **débogage** est une compétence importante à maîtriser, aussi bien pour les développeurs que pour les pentesters. Le terme "débogage" (en anglais _debugging_) signifie **trouver et supprimer les problèmes** (ou _bugs_) présents dans notre code – d’où le nom _de-bugging_.

Lorsque l’on développe un programme, on rencontre très souvent des bugs dans notre code. Il n’est **pas efficace** de simplement modifier le code à l’aveugle jusqu’à ce qu’il fonctionne comme prévu. À la place, on effectue un **débogage**, en posant des **points d’arrêt** (_breakpoints_) pour **observer le comportement du programme à chaque étape**, et **suivre comment les données évoluent** entre ces points.

Cela nous donne une idée claire de ce qui provoque le bug.

***

### <mark style="color:blue;">🧑‍💻</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Déboguer du code haut niveau vs assembleur**</mark>

* Dans un **langage de haut niveau** (C, Python, etc.), on peut placer des **points d’arrêt sur des lignes précises du code source**, et faire tourner le programme dans un **débogueur** pour observer ce qui se passe.
* En **assembleur**, on travaille avec du **code machine** représenté sous forme d’instructions assembleur.\
  → Les **points d’arrêt** sont alors **posés sur des adresses mémoire**, là où le code binaire est chargé.

***

### <mark style="color:blue;">🧰</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Outils de débogage**</mark>

Pour déboguer nos programmes binaires, nous allons utiliser un débogueur bien connu sous Linux : **GDB (GNU Debugger)**.

D’autres outils similaires existent :

* Pour **Linux** :
  * `Radare2`,
  * `EDB` (Enhanced Debugger),
  * `Hopper`
* Pour **Windows** :
  * `Immunity Debugger`,
  * `WinGDB`
* Et des outils **multi-plateformes très puissants** comme :
  * `IDA Pro`
  * `Ghidra`

***

### <mark style="color:blue;">🐧 Pourquoi GDB ?</mark>

Dans ce module, nous utiliserons **GDB**, car c’est le **plus fiable pour les binaires Linux**.\
Pourquoi ?

* Parce qu’il est **développé et maintenu par GNU**
* Il offre donc une **excellente intégration avec le système Linux** et ses composants

***

### <mark style="color:blue;">Installation</mark>

```sh
sudo apt-get update
sudo apt-get install gdb
```

{% hint style="info" %}
One of the great features of `GDB` is its support for third-party plugins. An excellent plugin that is well maintained and has good documentation is [GEF](https://github.com/hugsy/gef). GEF is a free and open-source GDB plugin that is built precisely for reverse engineering and binary exploitation. This fact makes it a great tool to learn.
{% endhint %}

```sh
wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```

***

### <mark style="color:blue;">Getting Started</mark>

Now that we have both tools installed, we can run gdb to debug our `HelloWorld` binary using the following commands, and GEF will be loaded automatically:

```sh
gdb -q ./helloWorld
...SNIP...
gef➤
```

```sh
mrroboteLiot_1@htb[/htb]$ ./assembler.sh helloWorld.s -g
...SNIP...
gef➤
```

***

### <mark style="color:blue;">Info</mark>

Once `GDB` is started, we can use the `info` command to view general information about the program, like its functions or variables.

<mark style="color:green;">**Functions**</mark>

To start, we will use the `info` command to check which `functions` are defined within the binary:

```asm
gef➤  info functions

All defined functions:

Non-debugging symbols:
0x0000000000401000  _start
```

As we can see, we found our main `_start` function.

<mark style="color:green;">**Variables**</mark>

We can also use the `info variables` command to view all available variables within the program:

```asm
gef➤  info variables

All defined variables:

Non-debugging symbols:
0x0000000000402000  message
0x0000000000402012  __bss_start
0x0000000000402012  _edata
0x0000000000402018  _end
```

As we can see, we find the `message`, along with some other default variables that define memory segments. We can do many things with functions, but we will focus on two main points: Disassembly and Breakpoints.

***

### <mark style="color:blue;">Disassemble</mark>

To view the instructions within a specific function, we can use the `disassemble` or `disas` command along with the function name, as follows:

```asm
gef➤  disas _start

Dump of assembler code for function _start:
   0x0000000000401000 <+0>:	mov    eax,0x1
   0x0000000000401005 <+5>:	mov    edi,0x1
   0x000000000040100a <+10>:	movabs rsi,0x402000
   0x0000000000401014 <+20>:	mov    edx,0x12
   0x0000000000401019 <+25>:	syscall
   0x000000000040101b <+27>:	mov    eax,0x3c
   0x0000000000401020 <+32>:	mov    edi,0x0
   0x0000000000401025 <+37>:	syscall
End of assembler dump.
```

***

Comme nous pouvons le voir, la sortie que nous avons obtenue **ressemble fortement à notre code assembleur** ainsi qu’à la **sortie de désassemblage** que nous avions obtenue avec `objdump` dans la section précédente.

Nous devons nous concentrer sur **l’élément principal de ce désassemblage** :\
👉 **les adresses mémoire** de chaque **instruction** et de chaque **opérande** (c’est-à-dire les **arguments**).

***

#### <mark style="color:green;">🔍 Pourquoi ces adresses sont importantes ?</mark>

Avoir l’adresse mémoire d’une instruction ou d’un argument est **essentiel** pour :

* **Examiner la valeur d’une variable ou d’un registre** pendant le débogage,
* **Placer des points d’arrêt (breakpoints)** à des endroits précis dans le programme.

***

#### <mark style="color:green;">🧠 Pourquoi certaines adresses commencent par</mark> <mark style="color:green;"></mark><mark style="color:green;">`0x00000000004xxxxx`</mark> <mark style="color:green;"></mark><mark style="color:green;">?</mark>

Pendant le débogage, tu remarqueras que **certaines adresses mémoire ont ce format** :

```
0x00000000004xxxxx
```

Et non pas ce format brut habituel :

```
0xffffffffaa8a25ff
```

***

👉 Cela vient de l'utilisation de **l’adressage relatif à `$rip`** (le pointeur d’instruction) dans les **exécutables position-indépendants** (**PIE – Position-Independent Executables**).

***

#### <mark style="color:green;">📦 Qu’est-ce que ça veut dire ?</mark>

Dans un **binaire PIE**, les **adresses mémoire ne sont pas absolues**.\
Elles sont **calculées par rapport à `$rip`**, c’est-à-dire à leur **position dans la RAM virtuelle du programme**.

* Avantage : rend les binaires **plus résistants à l’exploitation** (ex. : ROP, buffer overflow).
* Inconvénient : **plus difficile à déboguer** car les adresses **ne sont pas fixes**.

👉 Cette fonctionnalité peut parfois être **désactivée** pour **réduire la complexité** ou **permettre l’exploitation binaire** plus facilement lors de tests de sécurité.

***
