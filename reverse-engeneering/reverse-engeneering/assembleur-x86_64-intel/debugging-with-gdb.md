# Debugging with GDB

***

Now that we have the general information about our program, we will start running it and debugging it. Debugging consists mainly of four steps:

<table data-full-width="true"><thead><tr><th>Step</th><th>Description</th></tr></thead><tbody><tr><td><code>Break</code></td><td>Setting breakpoints at various points of interest</td></tr><tr><td><code>Examine</code></td><td>Running the program and examining the state of the program at these points</td></tr><tr><td><code>Step</code></td><td>Moving through the program to examine how it acts with each instruction and with user input</td></tr><tr><td><code>Modify</code></td><td>Modify values in specific registers or addresses at specific breakpoints, to study how it would affect the execution</td></tr></tbody></table>

***

### <mark style="color:blue;">Break</mark>

La première étape consiste à **poser un point d’arrêt**,pour arrêter l’exécution **à un endroit précis** du programme.

Cela permet de :

* Voir l’état du programme
* Voir les **valeurs des registres**
* **Exécuter instruction par instruction**

```asm
gef➤  b _start

Breakpoint 1 at 0x401000
```

Now, in order to start our program, we can use the `run` or `r` command:

{% code fullWidth="true" %}
```asm
gef➤  b _start
Breakpoint 1 at 0x401000
gef➤  r
Starting program: ./helloWorld 

Breakpoint 1, 0x0000000000401000 in _start ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffe310  →  0x0000000000000001
$rbp   : 0x0               
$rsi   : 0x0               
$rdi   : 0x0               
$rip   : 0x0000000000401000  →  <_start+0> mov eax, 0x1
...SNIP...
───────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffe310│+0x0000: 0x0000000000000001	 ← $rsp
0x00007fffffffe318│+0x0008: 0x00007fffffffe5a0  →  "./helloWorld"
...SNIP...
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400ffa                  add    BYTE PTR [rax], al
     0x400ffc                  add    BYTE PTR [rax], al
     0x400ffe                  add    BYTE PTR [rax], al
 →   0x401000 <_start+0>       mov    eax, 0x1
     0x401005 <_start+5>       mov    edi, 0x1
     0x40100a <_start+10>      movabs rsi, 0x402000
     0x401014 <_start+20>      mov    edx, 0x12
     0x401019 <_start+25>      syscall 
     0x40101b <_start+27>      mov    eax, 0x3c
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "helloWorld", stopped 0x401000 in _start (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401000 → _start()
────────────────────────────────────────────────────────────────────────────────────────────────────
```
{% endcode %}

{% hint style="info" %}
If we want to set a breakpoint at a certain address, like `_start+10`, we can either `b *_start+10` or `b *0x40100a`:
{% endhint %}

{% code fullWidth="true" %}
```asm
gef➤  b *0x40100a
Breakpoint 1 at 0x40100a
```
{% endcode %}

If we want to see what breakpoints we have at any point of the execution, we can use the `info breakpoint` command.&#x20;

{% hint style="info" %}
We can also `disable`, `enable`, or `delete` any breakpoint. Furthermore, GDB also supports setting conditional breaks that stop the execution when a specific condition is met.
{% endhint %}

***

### <mark style="color:blue;">Examine</mark>

***

<mark style="color:green;">**🧪 Étape suivante du débogage : examiner les registres et les adresses**</mark>

L’étape suivante du débogage consiste à **examiner les valeurs contenues dans les registres et à certaines adresses mémoire**.

Comme nous avons pu le voir dans la sortie du terminal précédente, **GEF** (GDB Enhanced Features) nous a automatiquement affiché beaucoup d’informations utiles au moment où le programme a atteint un **point d’arrêt (breakpoint)**.

C’est l’un des grands avantages du plugin **GEF** :\
Il **automatise de nombreuses étapes répétitives** que l’on fait habituellement à chaque point d’arrêt :

* inspection des **registres** (`RAX`, `RIP`, `RSP`, etc.)
* affichage de la **pile (stack)**
* et des **instructions assembleur en cours d’exécution**

***

<mark style="color:green;">**🔍 Examiner manuellement une adresse ou un registre**</mark>

Pour examiner **manuellement** une **adresse mémoire** ou un **registre**, on peut utiliser la commande `x` dans GDB.

<mark style="color:green;">**📌 Syntaxe :**</mark>

```
x/FMT ADRESSE
```

* `x` : commande pour "examine memory"
* `FMT` : le **format d’affichage**
* `ADRESSE` : l’adresse ou le registre que l’on souhaite examiner

> 💡 Si tu tapes `help x` dans GDB, il t’expliquera tout ça en détail.

***

<mark style="color:green;">**🧬 Le format**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`FMT`**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**peut contenir 3 parties :**</mark>

<table data-full-width="true"><thead><tr><th>Partie</th><th>Signification</th></tr></thead><tbody><tr><td><strong>Nombre</strong></td><td>combien d’éléments à afficher (ex : <code>10</code>)</td></tr><tr><td><strong>Taille</strong></td><td>taille de chaque élément : <code>b</code> (byte), <code>h</code> (2B), <code>w</code> (4B), <code>g</code> (8B)</td></tr><tr><td><strong>Type</strong></td><td>format d'affichage : <code>x</code> (hex), <code>d</code> (décimal), <code>i</code> (instruction), <code>s</code> (string), etc.</td></tr></tbody></table>

***

<mark style="color:green;">**✅ Exemples pratiques :**</mark>

<table data-full-width="true"><thead><tr><th>Commande</th><th>Signification</th></tr></thead><tbody><tr><td><code>x/x $rip</code></td><td>Examine 1 valeur en hex à l’adresse <code>RIP</code></td></tr><tr><td><code>x/10xw $rsp</code></td><td>Affiche 10 mots (4 octets) en hex depuis la pile</td></tr><tr><td><code>x/s $rsi</code></td><td>Affiche la <strong>chaîne de caractères</strong> pointée par <code>RSI</code></td></tr><tr><td><code>x/5i $rip</code></td><td>Affiche les <strong>5 prochaines instructions</strong> à exécuter</td></tr><tr><td><code>x/gx 0xdeadbeef</code></td><td>Affiche un <strong>quadword (8 octets)</strong> en hex à une adresse donnée</td></tr></tbody></table>

***

<table data-full-width="true"><thead><tr><th>Argument</th><th>Description</th><th>Example</th></tr></thead><tbody><tr><td><code>Count</code></td><td>The number of times we want to repeat the examine</td><td><code>2</code>, <code>3</code>, <code>10</code></td></tr><tr><td><code>Format</code></td><td>The format we want the result to be represented in</td><td><code>x(hex)</code>, <code>s(string)</code>, <code>i(instruction)</code></td></tr><tr><td><code>Size</code></td><td>The size of memory we want to examine</td><td><code>b(byte)</code>, <code>h(halfword)</code>, <code>w(word)</code>, <code>g(giant, 8 bytes)</code></td></tr></tbody></table>

***

<mark style="color:green;">**Instructions**</mark>

For example, if we wanted to examine the next four instructions in line, we will have to examine the `$rip` register (which holds the address of the next instruction), and use `4` for the `count`, `i` for the `format`, and `g` for the `size` (for 8-bytes or 64-bits).

{% code fullWidth="true" %}
```asm
gef➤  x/4ig $rip

=> 0x401000 <_start>:	mov    eax,0x1
   0x401005 <_start+5>:	mov    edi,0x1
   0x40100a <_start+10>:	movabs rsi,0x402000
   0x401014 <_start+20>:	mov    edx,0x12
```
{% endcode %}

<mark style="color:green;">**Strings**</mark>

We can also examine a variable stored at a specific memory address. We know that our `message` variable is stored at the `.data` section on address `0x402000` from our previous disassembly.&#x20;

We also see the upcoming command `movabs rsi, 0x402000`, so we may want to examine what is being moved from `0x402000`.

In this case, we will not put anything for the `Count`, as we only want one address (1 is the default), and will use `s` as the format to get it in a string format rather than in hex:

{% code fullWidth="true" %}
```asm
gef➤  x/s 0x402000

0x402000:	"Hello HTB Academy!"
```
{% endcode %}

<mark style="color:green;">**Addresses**</mark>

The most common format of examining is hex `x`. We often need to examine addresses and registers containing hex data, such as memory addresses, instructions, or binary data. Let us examine the same previous instruction, but in `hex` format, to see how it looks:

{% code fullWidth="true" %}
```bash
gef➤  x/wx 0x401000

0x401000 <_start>:	0x000001b8
```
{% endcode %}

We see instead of `mov eax,0x1`, we get `0x000001b8`, which is the hex representation of the `mov eax,0x1` machine code in little-endian formatting.

* This is read as: `b8 01 00 00`.

{% hint style="info" %}
We can also use `GEF` features to examine certain addresses. For example, at any point we can use the `registers` command to print out the current value of all registers:
{% endhint %}

{% code fullWidth="true" %}
```asm
gef➤  registers
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffe310  →  0x0000000000000001
$rbp   : 0x0               
$rsi   : 0x0               
$rdi   : 0x0               
$rip   : 0x0000000000401000  →  <_start+0> mov eax, 0x1
...SNIP...
```
{% endcode %}

***

### <mark style="color:blue;">Step</mark>

The third step of debugging is `stepping` through the program one instruction or line of code at a time. As we can see, we are currently at the very first instruction in our `helloWorld` program:

{% code fullWidth="true" %}
```asm
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400ffe                  add    BYTE PTR [rax], al
 →   0x401000 <_start+0>       mov    eax, 0x1
     0x401005 <_start+5>       mov    edi, 0x1
```
{% endcode %}

Note: the instruction shown with the `->` symbol is where we are at, and it has not yet been processed.

To move through the program, there are three different commands we can use: `stepi` and `step`.

<mark style="color:green;">**Step Instruction**</mark>

The `stepi` or `si` command will step through the assembly instructions one by one, which is the smallest level of steps possible while debugging. Let us use the `si` command to see how we get to the next instruction:

{% code fullWidth="true" %}
```bash
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
gef➤  si
0x0000000000401005 in _start ()
   0x400fff                  add    BYTE PTR [rax+0x1], bh
 →   0x401005 <_start+5>       mov    edi, 0x1
     0x40100a <_start+10>      movabs rsi, 0x402000
     0x401014 <_start+20>      mov    edx, 0x12
     0x401019 <_start+25>      syscall 
─────────────────────────────────────────────────────────────────────────────────────── threads ────
     [#0] Id 1, Name: "helloWorld", stopped 0x401005 in _start (), reason: SINGLE STEP
```
{% endcode %}

<mark style="color:green;">**Step Count**</mark>

Similarly to examine, we can repeat the `si` command by adding a number after it. For example, if we wanted to move 3 steps to reach the `syscall` instruction, we can do so as follows:

{% code fullWidth="true" %}
```asm
gef➤  si 3
0x0000000000401019 in _start ()
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401004 <_start+4>       add    BYTE PTR [rdi+0x1], bh
     0x40100a <_start+10>      movabs rsi, 0x402000
     0x401014 <_start+20>      mov    edx, 0x12
 →   0x401019 <_start+25>      syscall 
     0x40101b <_start+27>      mov    eax, 0x3c
     0x401020 <_start+32>      mov    edi, 0x0
     0x401025 <_start+37>      syscall 
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "helloWorld", stopped 0x401019 in _start (), reason: SINGLE STEP
```
{% endcode %}

As we can see, we stopped at the `syscall` instruction as expected.

{% hint style="info" %}
Tip: You can hit the `return`/`enter` empty in order to repeat the last command. Try hitting it at this stage, and you should make another 3 steps, and break at the other `syscall` instruction.
{% endhint %}

<mark style="color:green;">**Step**</mark>

The `step` or `s` command, on the other hand, will continue until the following line of code is reached or until it exits from the current function. If we run an assembly code, it will break when we exit the current function `_start`.

If there's a call to another function within this function, it'll break at the beginning of that function. Otherwise, it'll break after we exit this function after the program's end. Let us try using `s`, and see what happens:

{% code fullWidth="true" %}
```asm
gef➤  step

Single stepping until exit from function _start,
which has no line number information.
Hello HTB Academy!
[Inferior 1 (process 14732) exited normally]
```
{% endcode %}

We see that the execution continued until we reached the exit from the `_start` function, so we reached the end of the program and `exited normally` without any errors. We also see that `GDB` printed the program's output `Hello HTB Academy!` as well.

{% hint style="info" %}
PS

> **Note :** Il existe aussi la commande **`next`** (ou **`n`**), qui continue l’exécution jusqu’à la ligne suivante, **mais sans entrer dans les fonctions appelées sur cette ligne**, contrairement à **`step`** qui s’arrête à l’intérieur de ces fonctions.
>
> Il existe également la commande **`nexti`** (ou **`ni`**), qui est similaire à **`si`** (step instruction), **mais qui ignore les appels de fonctions**. Nous verrons son fonctionnement plus en détail plus tard dans le module.

👉 En résumé rapide :

* `step (s)` : entre dans les fonctions
* `next (n)` : n’entre pas dans les fonctions
* `si` : avance instruction par instruction (assembleur)
* `ni` : avance instruction par instruction **sans entrer dans les appels de fonctions**
{% endhint %}

***

### <mark style="color:blue;">Modify</mark>

The final step of debugging is `modifying` values in registers and addresses at a certain point of execution. This helps us in seeing how this would affect the execution of the program.

<mark style="color:green;">**Addresses**</mark>

To modify values in GDB, we can use the `set` command. However, we will utilize the `patch` command in `GEF` to make this step much easier. Let's enter `help patch` in GDB to get its help menu:

{% code fullWidth="true" %}
```asm
gef➤  help patch

Write specified values to the specified address.
Syntax: patch (qword|dword|word|byte) LOCATION VALUES
patch string LOCATION "double-escaped string"
...SNIP...
```
{% endcode %}

As we can see, we have to provide the `type/size` of the new value, the `location` to be stored, and the `value` we want to use. So, let's try changing the string stored in the `.data` section (at address `0x402000` as we saw earlier) to the string `Patched!\n`.

We will break at the first `syscall` at `0x401019`, and then do the patch, as follows:

{% code fullWidth="true" %}
```asm
gef➤  break *0x401019

Breakpoint 1 at 0x401019
gef➤  r
gef➤  patch string 0x402000 "Patched!\\x0a"
gef➤  c

Continuing.
Patched!
 Academy!
```
{% endcode %}

We see that we successfully modified the string and got `Patched!\n Academy!` instead of the old string. Notice how we used `\x0a` for adding a new line after our string.

<mark style="color:green;">**Registers**</mark>

We also note that we did not replace the entire string. This is because we only modified the characters up to the length of our string and left the remainder of the old string. Finally, the `write` system call specified a length of `0x12` of bytes to be printed.

To fix this, let's modify the value stored in `$rdx` to the length of our string, which is `0x9`. We will only patch a size of one byte. We will go into details of how `syscall` works later in the module. Let us demonstrate using `set` to modify `$rdx`, as follows:

{% code fullWidth="true" %}
```asm
gef➤  break *0x401019

Breakpoint 1 at 0x401019
gef➤  r
gef➤  patch string 0x402000 "Patched!\\x0a"
gef➤  set $rdx=0x9
gef➤  c

Continuing.
Patched!
```
{% endcode %}

***
