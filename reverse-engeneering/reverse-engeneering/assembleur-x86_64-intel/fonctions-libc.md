# Fonctions Libc

***

### <mark style="color:red;">Fonctions Libc</mark>

Jusqu’à présent, nous avons seulement affiché des nombres de Fibonacci inférieurs à 10. Mais de cette manière, notre programme est statique et affichera le même résultat à chaque exécution. Pour le rendre plus dynamique, nous pouvons demander à l’utilisateur le nombre maximal de Fibonacci qu’il souhaite afficher, puis l’utiliser avec `cmp`. Avant de commencer, rappelons la convention d’appel de fonction :

* Sauvegarder les registres sur la pile (Caller Saved)
* Passer les arguments de fonction (comme pour les appels système)
* Corriger l’alignement de la pile
* Obtenir la valeur de retour de la fonction (dans `rax`)

Alors, importons notre fonction et commençons par les étapes de la convention d’appel.

***

### <mark style="color:blue;">Importer les fonctions libc</mark>

Pour ce faire, nous pouvons utiliser la fonction `scanf` de la libc pour prendre une entrée utilisateur et la convertir correctement en entier, que nous utiliserons ensuite avec `cmp`. D’abord, nous devons importer `scanf`, comme suit :

```nasm
global  _start
extern  printf, scanf
```

Nous pouvons maintenant commencer à écrire une nouvelle procédure, `getInput`, afin de pouvoir l’appeler lorsque nécessaire :

```nasm
getInput:
    ; call scanf
```

***

### <mark style="color:blue;">Sauvegarder les registres</mark>

Comme nous sommes au début de notre programme et que nous n’avons encore utilisé aucun registre, nous n’avons pas à nous soucier de sauvegarder les registres sur la pile. Nous pouvons donc passer à l’étape suivante et fournir les arguments nécessaires à `scanf`.

***

### <mark style="color:blue;">Arguments de fonction</mark>

Ensuite, nous devons savoir quels arguments sont acceptés par `scanf`, comme suit :

```bash
mrroboteLiot_1@htb[/htb]$ man -s 3 scanf
```

...SNIP...

```c
int scanf(const char *format, ...);
```

Nous voyons que, tout comme `printf`, `scanf` accepte un format d’entrée et un tampon (buffer) dans lequel enregistrer la saisie de l’utilisateur. Commençons donc par ajouter la variable `inFormat` :

```nasm
section .data
    message db "Please input max Fn", 0x0a
    outFormat db  "%d", 0x0a, 0x00
    inFormat db  "%d", 0x00
```

Nous avons également modifié notre message d’introduction de `Fibonacci Sequence:` en `Please input max Fn`, pour indiquer à l’utilisateur ce que l’on attend de lui.

Ensuite, nous devons définir un espace tampon pour stocker l’entrée. Comme mentionné dans la section sur l’architecture du processeur, l’espace tampon non initialisé doit être stocké dans le segment mémoire `.bss`. Au début de notre code assembleur, nous devons donc l’ajouter sous le label `.bss` et utiliser `resb 1` pour demander à NASM de réserver 1 octet d’espace tampon, comme suit :

```nasm
section .bss
    userInput resb 1
```

Nous pouvons maintenant définir nos arguments de fonction dans la procédure `getInput` :

```nasm
getInput:
    mov rdi, inFormat   ; définir le 1er paramètre (inFormat)
    mov rsi, userInput  ; définir le 2e paramètre (userInput)
```

***

### <mark style="color:blue;">Alignement de la pile</mark>

Ensuite, nous devons nous assurer que notre pile est alignée sur une frontière de 16 octets. Nous sommes actuellement dans la procédure `getInput`, donc nous avons 1 instruction `call` et aucune instruction `push`, ce qui donne une frontière de 8 octets. Nous pouvons donc utiliser `sub` pour corriger `rsp`, comme suit :

```nasm
getInput:
    sub rsp, 8
    ; call scanf
    add rsp, 8
```

Nous pourrions aussi faire un `push rax` à la place, ce qui alignerait également correctement la pile. De cette manière, notre pile serait parfaitement alignée sur 16 octets.

***

### <mark style="color:blue;">Appel de la fonction</mark>

Maintenant que les arguments sont définis, appelons `scanf`, comme suit :

```nasm
getInput:
    sub rsp, 8          ; aligner la pile à 16 octets
    mov rdi, inFormat   ; définir le 1er paramètre (inFormat)
    mov rsi, userInput  ; définir le 2e paramètre (userInput)
    call scanf          ; scanf(inFormat, userInput)
    add rsp, 8          ; restaurer l’alignement de la pile
    ret
```

Nous ajouterons également `call getInput` dans `_start`, pour que l’on accède à cette procédure juste après l’affichage du message d’intro, comme suit :

```nasm
section .text
_start:
    call printMessage   ; afficher le message d’intro
    call getInput       ; obtenir le nombre max
    call initFib        ; définir les valeurs initiales de Fibonacci
    call loopFib        ; calculer les nombres de Fibonacci
    call Exit           ; quitter le programme
```

***

### <mark style="color:blue;">Utiliser l’entrée utilisateur</mark>

Enfin, nous devons utiliser la saisie de l’utilisateur. Pour ce faire, au lieu d’utiliser un `10` statique dans `cmp rbx, 10`, nous le remplaçons par `cmp rbx, [userInput]`, comme suit :

```nasm
loopFib:
    ...SNIP...
    cmp rbx,[userInput] ; faire rbx - userInput
    js loopFib          ; sauter si le résultat est < 0
    ret
```

**Remarque :** Nous avons utilisé `[userInput]` au lieu de `userInput`, car nous voulons comparer avec la **valeur finale**, et non avec l’adresse du pointeur.

***

### <mark style="color:blue;">Code complet</mark>

Avec tout cela en place, notre code final complet devrait ressembler à ceci :

```asm
global  _start
extern  printf, scanf

section .data
    message db "Please input max Fn", 0x0a
    outFormat db  "%d", 0x0a, 0x00
    inFormat db  "%d", 0x00

section .bss
    userInput resb 1

section .text
_start:
    call printMessage   ; afficher le message d’intro
    call getInput       ; obtenir le nombre max
    call initFib        ; définir les valeurs initiales de Fibonacci
    call loopFib        ; calculer les nombres de Fibonacci
    call Exit           ; quitter le programme

printMessage:
    ...SNIP...

getInput:
    sub rsp, 8          ; aligner la pile à 16 octets
    mov rdi, inFormat   ; définir le 1er paramètre (inFormat)
    mov rsi, userInput  ; définir le 2e paramètre (userInput)
    call scanf          ; scanf(inFormat, userInput)
    add rsp, 8          ; restaurer l’alignement de la pile
    ret

initFib:
    ...SNIP...

printFib:
    ...SNIP...

loopFib:
    ...SNIP...
    cmp rbx,[userInput] ; faire rbx - userInput
    js loopFib          ; sauter si le résultat est < 0
    ret

Exit:
    ...SNIP...
```

***

### <mark style="color:blue;">Éditeur de liens dynamique</mark>

Assemblons notre code, lions-le, et essayons d’imprimer les nombres de Fibonacci jusqu’à 100 :

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot_1@htb[/htb]$ nasm -f elf64 fib.s &&  ld fib.o -o fib -lc --dynamic-linker /lib64/ld-linux-x86-64.so.2 && ./fib
```
{% endcode %}

```
Please input max Fn:
100
1
1
2
3
5
8
13
21
34
55
89
```

Nous voyons que notre code a fonctionné comme prévu et a imprimé les nombres de Fibonacci inférieurs au nombre que nous avons spécifié. Avec cela, nous pouvons terminer notre projet de module et créer un programme qui calcule et affiche les nombres de Fibonacci en fonction d’une entrée utilisateur, en utilisant **rien d’autre qu’assembleur**.

De plus, nous devons apprendre à transformer le code assembleur en **shellcode machine**, que nous pourrons ensuite utiliser directement dans nos charges utiles lors de l’exploitation binaire.

***
