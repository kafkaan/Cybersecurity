# Syscalls

***

## <mark style="color:red;">📞</mark> <mark style="color:red;"></mark><mark style="color:red;">**Appels Système (Syscalls)**</mark>

***

#### <mark style="color:green;">🧠</mark> <mark style="color:green;"></mark><mark style="color:green;">**Introduction**</mark>

Même si nous communiquons directement avec le processeur via des instructions machines en assembleur,nous **n’avons pas besoin d’exécuter chaque type d’opération avec des instructions machines basiques**.

Les programmes utilisent régulièrement de **nombreux types d’opérations**.Le **système d’exploitation** peut nous aider à travers les **appels système (syscalls)**,afin de ne **pas devoir implémenter manuellement ces opérations chaque fois**.

***

### <mark style="color:green;">🖥️ Exemple</mark>

Supposons que nous voulons **écrire quelque chose à l’écran sans syscall** :

* Il faudrait parler à la **mémoire vidéo**,
* gérer l’**encodage**,
* **envoyer l’entrée à l’écran**,
* et **attendre une confirmation**.

➡️ Si on devait faire ça **juste pour afficher un caractère**, le code assembleur serait **beaucoup plus long**.

***

### <mark style="color:blue;">🐧</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Syscalls Linux**</mark>

Un syscall est **comme une fonction globale** fournie par le **noyau Linux**, écrite en C.

Un syscall :

* utilise les **registres** pour recevoir ses arguments
* exécute une **fonction système** interne

Exemple :\
Pour afficher une chaîne à l’écran, on peut utiliser le syscall `write`,\
lui fournir :

* la chaîne
* le descripteur de fichier
* la longueur\
  et ensuite faire un `syscall` pour l’exécuter.

***

### <mark style="color:blue;">📚 Trouver les Syscalls</mark>

On peut voir la liste des syscalls (et leurs numéros) dans ce fichier système :

```bash
cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h
```

Extrait :

```c
#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_close 3
...
```

🔹 Ce fichier **assigne un numéro à chaque syscall**.

📝 **Remarque** :

* En 32-bit (`x86`), c’est le fichier `unistd_32.h` qui contient les numéros.

***

### <mark style="color:blue;">🧪</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Pratique avec**</mark><mark style="color:blue;">**&#x20;**</mark><mark style="color:blue;">**`write`**</mark>

On va utiliser `write` pour afficher une intro `"Fibonacci Sequence"` en début de programme.\
(On n'affiche pas encore les nombres Fibonacci.)

***

### <mark style="color:blue;">📖 Arguments de</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`write`</mark>

Pour voir les arguments attendus par un syscall :

```bash
man -s 2 write
```

Sortie :

```c
ssize_t write(int fd, const void *buf, size_t count);
```

Donc, `write()` attend :

1. `fd` — le **descripteur de fichier** (1 = stdout)
2. `buf` — **pointeur vers la chaîne**
3. `count` — la **longueur à écrire**

***

### <mark style="color:blue;">🧰 Convention d’appel syscall (x86\_64)</mark>

<table data-full-width="true"><thead><tr><th>Description</th><th>Registre 64 bits</th><th>Registre 8 bits</th></tr></thead><tbody><tr><td>Numéro de syscall</td><td><code>rax</code></td><td><code>al</code></td></tr><tr><td>1er argument</td><td><code>rdi</code></td><td><code>dil</code></td></tr><tr><td>2e argument</td><td><code>rsi</code></td><td><code>sil</code></td></tr><tr><td>3e argument</td><td><code>rdx</code></td><td><code>dl</code></td></tr><tr><td>4e argument</td><td><code>rcx</code></td><td><code>cl</code></td></tr><tr><td>5e argument</td><td><code>r8</code></td><td><code>r8b</code></td></tr><tr><td>6e argument</td><td><code>r9</code></td><td><code>r9b</code></td></tr></tbody></table>

📝 **Remarque** : `rax` contient aussi la **valeur de retour** d’un syscall.

***

### <mark style="color:blue;">🛠️ Préparer le syscall</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`write`</mark>

#### Valeurs :

* `rdi = 1` (stdout)
* `rsi = message` (pointeur vers la chaîne)
* `rdx = 20` (longueur en octets)

Mais on ne peut pas stocker une longue chaîne directement dans un registre.\
👉 On la définit dans la section `.data` :

```nasm
section .data
    message db "Fibonacci Sequence:", 0x0a
```

> `0x0a` = caractère de **nouvelle ligne**

***

### <mark style="color:blue;">✅ Code complet :</mark>

```nasm
global _start

section .data
    message db "Fibonacci Sequence:", 0x0a

section .text
_start:
    mov rax, 1        ; numéro du syscall (write)
    mov rdi, 1        ; fd 1 → stdout
    mov rsi, message  ; pointeur vers la chaîne
    mov rdx, 20       ; longueur à écrire
    syscall           ; appel système

    xor rax, rax      ; initialiser rax à 0
    xor rbx, rbx      ; initialiser rbx à 0
    inc rbx           ; rbx = 1

loopFib:
    add rax, rbx
    xchg rax, rbx
    cmp rbx, 10
    js loopFib
```

***

### <mark style="color:blue;">🧪 Tester avec GDB :</mark>

```bash
gdb -q ./fib
```

Dans GDB :

```gdb
disas _start
b *_start+17
r
```

On observe :

```
$rax = 0x1        ; syscall numéro
$rdi = 0x1        ; fd = stdout
$rsi = pointeur vers "Fibonacci Sequence:"
$rdx = 0x14       ; longueur = 20
```

➡️ La chaîne s’affiche bien.

***

### <mark style="color:blue;">❌</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Segmentation fault**</mark> <mark style="color:blue;"></mark><mark style="color:blue;">?</mark>

Si on n'ajoute **aucun syscall de sortie**, le programme se termine brutalement :

```bash
[1] 107348 segmentation fault ./fib
```

***

### <mark style="color:blue;">✅</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Ajouter un syscall**</mark><mark style="color:blue;">**&#x20;**</mark><mark style="color:blue;">**`exit`**</mark>

Trouver le numéro :

```bash
grep exit /usr/include/x86_64-linux-gnu/asm/unistd_64.h
```

Résultat :

```c
#define __NR_exit 60
```

Voir les arguments :

```bash
man -s 2 exit
```

Résultat :

```c
void _exit(int status);
```

➡️ Il faut passer un **code de sortie** (0 = OK, 1 = erreur, etc.)

***

#### ✅ Code pour `exit` :

```nasm
mov rax, 60     ; numéro du syscall exit
mov rdi, 0      ; code de sortie = 0
syscall
```

***

### <mark style="color:blue;">🔁 Code final :</mark>

```nasm
global _start

section .data
    message db "Fibonacci Sequence:", 0x0a

section .text
_start:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    mov rdx, 20
    syscall

    xor rax, rax
    xor rbx, rbx
    inc rbx

loopFib:
    add rax, rbx
    xchg rax, rbx
    cmp rbx, 10
    js loopFib

    mov rax, 60
    mov rdi, 0
    syscall
```

***

### 🧪 Vérification du code de sortie :

```bash
./assembler.sh fib.s
echo $?
```

Résultat :

```bash
0
```

✅ Le code de sortie est bien 0.

***
