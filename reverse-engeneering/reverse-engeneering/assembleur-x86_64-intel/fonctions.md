# Fonctions

***

## <mark style="color:red;">⚙️</mark> <mark style="color:red;"></mark><mark style="color:red;">**Fonctions**</mark>

***

Nous devrions maintenant comprendre les différentes instructions de branchement et de contrôle utilisées pour gérer le **flux d’exécution** d’un programme.

Nous devrions aussi bien comprendre les **procédures** et l’usage de **`call`** pour y accéder.

Il est donc temps de se concentrer sur **l’appel de fonctions**.

***

### <mark style="color:blue;">📏</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Convention d’appel des fonctions (Calling Convention)**</mark>

Les **fonctions** sont une **forme spécialisée de procédure**.\
Mais contrairement aux procédures simples, les fonctions sont souvent plus **complexes** et doivent **utiliser la pile** et **tous les registres**.

👉 Donc on **ne peut pas** simplement appeler une fonction comme on le fait avec une procédure.

***

#### <mark style="color:green;">Avant d'appeler une fonction, on doit :</mark>

1. **Sauvegarder les registres** (ceux que l’appel va modifier)
2. **Passer les arguments** (comme pour un syscall)
3. **Aligner la pile (stack)**
4. **Lire la valeur de retour** dans `rax`

> C’est **similaire aux syscalls**, sauf que :
>
> * pour les syscalls, on met le **numéro dans `rax`**
> * pour les fonctions, on fait simplement `call nom_fonction`
> * les syscalls **n’ont pas besoin d’aligner la pile**, mais les fonctions oui

***

### <mark style="color:blue;">✍️</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Écrire des fonctions**</mark>

Du **point de vue de la fonction appelée**, il faut :

1. **Sauvegarder les registres callee-saved** (`rbx`, `rbp`)
2. **Lire les arguments** passés dans les bons registres
3. **Aligner la pile**
4. **Placer la valeur de retour dans `rax`**

Ces éléments sont souvent gérés dans le **prologue** (début) et **épilogue** (fin) de la fonction.

***

📝 Dans ce module, **on ne va qu’appeler des fonctions externes**,donc on va se concentrer sur la **préparation correcte des appels**.

***

### <mark style="color:blue;">🔌</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Utilisation de fonctions externes**</mark>

On veut **afficher le nombre Fibonacci courant** à chaque itération de la boucle `loopFib`.

Mais on ne peut pas utiliser `write` car il n’affiche que des **chaînes ASCII**,\
et on devrait convertir nos nombres → ce serait trop complexe.

***

#### <mark style="color:green;">✅ Solution : utiliser</mark> <mark style="color:green;"></mark><mark style="color:green;">`printf`</mark> <mark style="color:green;"></mark><mark style="color:green;">de la</mark> <mark style="color:green;"></mark><mark style="color:green;">**librairie C (libc)**</mark>

La **libc** (utilisée dans les programmes C) contient **plein de fonctions utiles**.

✅ `printf` peut :

* **prendre un nombre**
* et l’**afficher** automatiquement sous forme d’entier (`%d`)

Mais pour l’utiliser :

* on doit l’**importer avec `extern`**
* et **linker dynamiquement avec libc** lors de l’édition de liens avec `ld`

***

### <mark style="color:blue;">📥</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Importer**</mark><mark style="color:blue;">**&#x20;**</mark><mark style="color:blue;">**`printf`**</mark>

```nasm
global _start
extern printf
```

➡️ Cela permet d’**utiliser `call printf`** plus tard dans le code.

***

### <mark style="color:blue;">💾</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Sauvegarde des registres**</mark>

On va créer une **procédure `printFib`** pour contenir l’appel à la fonction.

Première étape : **sauvegarder `rax` et `rbx`** (qu’on utilise) :

```asm
printFib:
    push rax
    push rbx
    ; appel de fonction ici
    pop rbx
    pop rax
    ret
```

***

### <mark style="color:blue;">🧮</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Arguments de la fonction**</mark>

Les arguments sont passés comme dans les syscalls.

Utilise :

```bash
man -s 3 printf
```

Sortie :

```c
int printf(const char *format, ...);
```

🔹 Le premier argument est un **pointeur vers une chaîne de format**\
🔹 Les suivants sont les **valeurs à afficher**

***

#### <mark style="color:green;">🎯 Format : entier</mark>

```nasm
section .data
    outFormat db "%d", 0x0a, 0x00
```

* `%d` → afficher un entier
* `0x0a` → saut de ligne
* `0x00` → **fin de chaîne** (`null terminator`)

***

#### <mark style="color:green;">🔧 Définir les registres</mark>

```asm
printFib:
    push rax
    push rbx
    mov rdi, outFormat  ; 1er argument → format string
    mov rsi, rbx        ; 2e argument → nombre à afficher
    pop rbx
    pop rax
    ret
```

***

### <mark style="color:blue;">📐</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Alignement de la pile (Stack Alignment)**</mark>

Avant un `call`, la **pile doit être alignée sur 16 octets**.

💡 Chaque :

* `call` pousse 8 octets (l’adresse de retour)
* `push` pousse 8 octets

Si on a **2 push + 1 call**, on a 24 octets → pas aligné.

Pour corriger :

```nasm
sub rsp, 8     ; ajoute 8 octets fictifs pour aligner
call fonction
add rsp, 8
```

Mais dans notre cas, **2 push + 1 call + 1 ret** = total 32 octets → ✅ déjà aligné.

***

### <mark style="color:blue;">🔁</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Appel de fonction réel**</mark>

```asm
printFib:
    push rax
    push rbx
    mov rdi, outFormat
    mov rsi, rbx
    call printf
    pop rbx
    pop rax
    ret
```

***

### <mark style="color:blue;">🔂</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Intégrer dans la boucle**</mark>

```nasm
loopFib:
    call printFib
    add rax, rbx
    xchg rax, rbx
    cmp rbx, 10
    js loopFib
    ret
```

***

### <mark style="color:blue;">🧩</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Code complet**</mark>

{% code fullWidth="true" %}
```asm
global _start
extern printf

section .data
    message db "Fibonacci Sequence:", 0x0a
    outFormat db "%d", 0x0a, 0x00

section .text
_start:
    call printMessage
    call initFib
    call loopFib
    call Exit

printMessage:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    mov rdx, 20
    syscall
    ret

initFib:
    xor rax, rax
    xor rbx, rbx
    inc rbx
    ret

printFib:
    push rax
    push rbx
    mov rdi, outFormat
    mov rsi, rbx
    call printf
    pop rbx
    pop rax
    ret

loopFib:
    call printFib
    add rax, rbx
    xchg rax, rbx
    cmp rbx, 10
    js loopFib
    ret

Exit:
    mov rax, 60
    mov rdi, 0
    syscall
```
{% endcode %}

***

### <mark style="color:blue;">🧱</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Linker dynamiquement avec**</mark><mark style="color:blue;">**&#x20;**</mark><mark style="color:blue;">**`libc`**</mark>

```bash
nasm -f elf64 fib.s
ld fib.o -o fib -lc --dynamic-linker /lib64/ld-linux-x86-64.so.2
./fib
```

***

### <mark style="color:blue;">✅ Résultat :</mark>

```bash
1
1
2
3
5
8
```

> Grâce à `printf`, on affiche **automatiquement** les nombres sans convertir en ASCII nous-mêmes.

***
