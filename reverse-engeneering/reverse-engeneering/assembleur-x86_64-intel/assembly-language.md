# Assembly Language

***

### <mark style="color:red;">Introduction</mark>

:desktop:  <mark style="color:green;">**Interaction avec les appareils :**</mark>\
La majorité de nos interactions avec les ordinateurs personnels et les smartphones se fait à travers le système d’exploitation et diverses applications.

:tongue: <mark style="color:green;">**Langages de haut niveau :**</mark>\
Ces applications sont généralement développées avec des langages de haut niveau comme C++, Java, Python, entre autres.

:minidisc: <mark style="color:green;">**Composants matériels :**</mark>\
Chaque appareil possède u**n&#x20;**<mark style="color:orange;">**processeur central (CPU)**</mark> qui exécute les processus nécessaires au fonctionnement des systèmes et applications, ainsi que de **la&#x20;**<mark style="color:orange;">**mémoire vive (RAM)**</mark>**,** de la mémoire vidéo, et d’autres composants similaires.

:octagonal\_sign: <mark style="color:green;">**Limite des processeurs :**</mark>\
Les composants physiques, comme le processeur, ne comprennent pas directement les langages de haut niveau. Ils ne peuvent traiter que des données binaires (des suites de 1 et de 0).

:person\_raising\_hand: <mark style="color:green;">**Rôle du langage assembleur (Assembly) :**</mark>\
C’est là qu’intervient le langage assembleur, un langage de bas niveau qui permet d’écrire des instructions que le processeur peut comprendre directement.

<mark style="color:green;">**Problème du binaire pur :**</mark>\
Écrire directement en binaire serait très difficile pour l’être humain, car il faudrait constamment consulter des manuels pour connaître le code hexadécimal de chaque instruction machine.

<mark style="color:green;">**Avantage de l’assembleur :**</mark>\
Le langage assembleur permet aux développeurs d’écrire des instructions lisibles par l’humain, qui sont ensuite traduites (assemblées) en code machine exécutable par le processeur.

<mark style="color:green;">**Exemple comparatif :**</mark>\
Par exemple, l’instruction assembleur `add rax, 1` est bien plus intuitive que son équivalent en shellcode hexadécimal `4883C001`, et encore plus que sa version binaire `01001000 10000011 11000000 00000001`.

<mark style="color:green;">**Shellcode et code machine :**</mark>\
Le code machine est souvent représenté sous forme de shellcode, une version hexadécimale des instructions binaires. Le shellcode peut être reconverti en assembleur ou bien chargé directement en mémoire pour être exécuté.

***

### <mark style="color:red;">High-level vs. Low-level</mark>

* Comme il existe différentes conceptions de processeurs, <mark style="color:orange;">**chaque processeur comprend un ensemble différent d'instructions machine et un langage assembleur différent.**</mark>
* Dans le passé, les applications devaient être écrites en assembleur pour chaque processeur, donc il n'était pas facile de développer une application pour plusieurs processeurs.
* Au début des années 1970, des langages de haut niveau (comme le C) ont été développés pour rendre possible l’écriture d’un seul code facile à comprendre qui peut fonctionner sur n’importe quel processeur sans avoir à le réécrire pour chaque processeur.\
  Pour être plus précis, cela a été rendu possible en créant des compilateurs pour chaque langage.

Lorsque le code de haut niveau est compilé, il est **traduit en instructions assembleur** pour le processeur pour lequel il est compilé, qui sont ensuite **assemblées en code machine** pour s’exécuter sur le processeur.\
C’est pourquoi des compilateurs sont créés pour différents langages et différents processeurs, afin de convertir le code de haut niveau en code assembleur puis en code machine correspondant au processeur exécutant ce code.

* Par la suite, des langages interprétés ont été développés, comme Python, PHP, Bash, JavaScript, et d'autres, qui ne sont généralement pas compilés mais interprétés pendant l'exécution.
* Ces types de langages utilisent des bibliothèques préconstruites pour exécuter leurs instructions.\
  Ces bibliothèques sont généralement écrites et compilées dans d'autres langages de haut niveau comme le C ou le C++.
* Ainsi, lorsque nous exécutons une commande dans un langage interprété, celui-ci utilise la bibliothèque compilée pour exécuter cette commande, qui utilise son code assembleur/code machine pour effectuer toutes les instructions nécessaires à l'exécution de cette commande sur le processeur.

***

### <mark style="color:red;">Compilation Stages</mark>

<figure><img src="../../../.gitbook/assets/image (140).png" alt=""><figcaption></figcaption></figure>

Let's take a basic '`Hello World!`' program that prints these words on the screen and show how it changes from high-level to machine code. In an interpreted language, like Python, it would be the following basic line:

```python
print("Hello World!")
```

If we run this Python line, it would be essentially executing the following `C` code:

```c
#include <unistd.h>

int main()
{
    write(1, "Hello World!", 12);
    _exit(0);
}
```

{% hint style="warning" %}
Note: the actual `C` source code is much longer, but the above is the essence of how the string '`Hello World!`' is printed. If you are ever interested in knowing more, you can check out the source code of the Python3 print function at this [link](https://github.com/python/cpython/blob/0332e569c12d3dc97171546c6dc10e42c27de34b/Python/bltinmodule.c#L1829) and this [link](https://github.com/python/cpython/blob/9975cc5008c795e069ce11e2dbed2110cc12e74e/Objects/fileobject.c#L119)
{% endhint %}

The above `C` code uses the Linux `write` syscall, built-in for processes to write to the screen. The same syscall called in Assembly looks like the following:

```asm
mov rax, 1
mov rdi, 1
mov rsi, message
mov rdx, 12
syscall

mov rax, 60
mov rdi, 0
syscall
```

```
Votre code: syscall
     ↓
Interruption système (trap)
     ↓
entry_SYSCALL_64 (assembleur kernel)
     ↓
sys_call_table[1] → sys_write
     ↓
SYSCALL_DEFINE3(write, ...) en C
     ↓
vfs_write() → file operations
     ↓
Driver du terminal/fichier
     ↓
Hardware (écran, disque...)
```

As we can see, when the `write` syscall is called in `C` or Assembly, both are using `1`, the text, and `12` as the arguments.

&#x20;This will be covered more in-depth later in the module. From this point, Assembly code, shellcode, and binary machine code are mostly identical but written in different formats. The previous Assembly code can be assembled into the following hex machine code (i.e., shellcode):

```shellcode
48 c7 c0 01
48 c7 c7 01
48 8b 34 25
48 c7 c2 0c
0f 05

48 c7 c0 3c
48 c7 c7 00
0f 05
```

Finally, for the processor to execute the instructions linked to this machine, it would have to be translated into binary, which would look like the following:

```binary
01001000 11000111 11000000 00000001
01001000 11000111 11000111 00000001
01001000 10001011 00110100 00100101
01001000 11000111 11000010 00001101 
00001111 00000101

01001000 11000111 11000000 00111100 
01001000 11000111 11000111 00000000 
00001111 00000101
```

A CPU uses different electrical charges for a `1` and a `0`, and hence can calculate these instructions from the binary data once it receives them.

{% hint style="info" %}
<mark style="color:green;">**Décodage de vos instructions**</mark>

```assembly
48 c7 c0 01 00 00 00  ; mov rax, 1      (7 bytes)
48 c7 c7 01 00 00 00  ; mov rdi, 1      (7 bytes)  
48 8b 34 25 XX XX XX XX ; mov rsi, [addr] (8 bytes)
48 c7 c2 0c 00 00 00  ; mov rdx, 12     (7 bytes)
0f 05                 ; syscall         (2 bytes)
48 c7 c0 3c 00 00 00  ; mov rax, 60     (7 bytes)
48 c7 c7 00 00 00 00  ; mov rdi, 0      (7 bytes)
0f 05                 ; syscall         (2 bytes)
```

***

<mark style="color:green;">**Format général**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

```
[Prefixes] [REX] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
```

<mark style="color:green;">**Décodage détaillé**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

**`48 c7 c0 01 00 00 00`** (mov rax, 1)

* `48` = **REX prefix** (indique 64-bit)
* `c7` = **Opcode** (MOV immediate vers registre)
* `c0` = **ModR/M** (spécifie RAX comme destination)
* `01 00 00 00` = **Immediate** (valeur 1 en little-endian 32-bit)

**`0f 05`** (syscall)

* `0f 05` = **Opcode sur 2 bytes** (instruction syscall)

***

<mark style="color:green;">**Comment le CPU lit ces instructions**</mark>

**1. Fetch (Récupération)**

```
CPU lit 1 byte à la fois depuis la mémoire :
Adresse 0x400000: 48
Adresse 0x400001: c7  
Adresse 0x400002: c0
...
```

**2. Decode (Décodage)**

```
1. CPU voit 48 → "OK, c'est un REX prefix, mode 64-bit"
2. CPU voit c7 → "Opcode MOV immediate"
3. CPU voit c0 → "ModR/M = registre RAX"
4. CPU sait qu'il faut lire 4 bytes d'immediate
5. CPU lit 01 00 00 00 → valeur 1
```

**3. Execute (Exécution)**

```
CPU charge 1 dans RAX
```

**Taille des instructions**

Les instructions x86-64 ont une **taille variable** :

* **Minimum** : 1 byte (`nop` = `90`)
* **Maximum** : 15 bytes
* **Vos instructions** : entre 2 et 8 bytes

**Lecture séquentielle**

```
Mémoire:  [48][c7][c0][01][00][00][00][48][c7][c7][01]...
Position:   0   1   2   3   4   5   6   7   8   9  10

CPU:
1. Lit position 0: 48 (REX)
2. Lit position 1: c7 (Opcode)  
3. Lit position 2: c0 (ModR/M)
4. Lit positions 3-6: immediate
5. Instruction terminée → avance à position 7
6. Répète...
```
{% endhint %}

{% hint style="warning" %}
**Remarque :** Avec les langages multiplateformes, comme Java, le code est compilé en _bytecode_ Java, qui est identique pour tous les processeurs/systèmes, puis il est compilé en code machine par l’environnement d’exécution Java local (_Java Runtime Environment_).\
C’est ce qi rend Java relativement plus lent que d’autres langages comme le C++, qui sont compilés directement en code machine.\
Les langages comme le C++ sont plus adaptés aux applications nécessitant beaucoup de ressources processeur, comme les jeux vidéo.
{% endhint %}

***
