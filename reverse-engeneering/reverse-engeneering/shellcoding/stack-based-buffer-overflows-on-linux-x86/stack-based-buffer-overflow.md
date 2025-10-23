# Stack-Based Buffer Overflow

***

### <mark style="color:red;">1️⃣ Qu’est-ce qu’un Buffer Overflow ?</mark>

* Un **buffer overflow** survient quand on écrit **plus de données** que la taille prévue d’un tampon mémoire.
* Résultat : on écrase d’autres zones mémoire (variables, adresses de retour).
* C’est une faille de sécurité majeure, utilisée pour détourner le flot du programme.

Langages vulnérables : **C / C++** (pas de protections automatiques).\
Langages protégés : **Java / Python** (vérifications automatiques).

***

### <mark style="color:red;">2️⃣ Organisation de la mémoire (ELF – Linux)</mark>

Lorsqu’un binaire ELF est chargé, les segments suivants sont placés en mémoire :

<table data-full-width="true"><thead><tr><th>Section</th><th>Rôle</th></tr></thead><tbody><tr><td><strong>.text</strong></td><td>Contient le code assembleur (instructions). Lecture seule.</td></tr><tr><td><strong>.data</strong></td><td>Contient les variables <strong>globales/statics initialisées</strong>.</td></tr><tr><td><strong>.bss</strong></td><td>Contient les variables <strong>globales/statics non initialisées</strong> (remplies de <code>0</code>). Exemple : <code>userInput resb 1</code>.</td></tr><tr><td><strong>Heap</strong></td><td>Mémoire dynamique (malloc/free). Croît vers les adresses hautes.</td></tr><tr><td><strong>Stack</strong></td><td>Pile d’exécution (LIFO). Contient adresses de retour, paramètres, variables locales. Croît vers les adresses basses.</td></tr></tbody></table>

<mark style="color:green;">**👉 Schéma mémoire simplifié :**</mark>

{% code fullWidth="true" %}
```
0xFFFFFFFF  ← Haut
[ Stack (pile) ]
[ espace vide ]
[ Heap (tas)  ]
[ .bss ]
[ .data ]
[ .text (code) ]
0x00000000  ← Bas
```
{% endcode %}

***

### <mark style="color:red;">3️⃣ Protections modernes</mark>

* **DEP (Data Execution Prevention)** → interdit d’exécuter du code dans certaines zones (stack).
* **ASLR (Address Space Layout Randomization)** → adresses mémoire aléatoires pour compliquer l’exploitation.
* **Bypass** possible avec :
  * **ROP (Return Oriented Programming)**
  * **fuites mémoire** pour contourner ASLR
* **Sans protection :** buffer overflow → injection de shellcode dans la pile → exécution directe.
* **Avec DEP :** impossible d’exécuter du code injecté dans la pile.
* **Avec ROP :** l’attaquant enchaîne des morceaux de code existants pour exécuter ses objectifs.
* **Avec ASLR :** les adresses changent aléatoirement → ROP devient très difficile sans fuite mémoire.

***

### <mark style="color:red;">4️⃣ Exemple de programme vulnérable</mark>

<mark style="color:green;">**bow.c :**</mark>

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int bowfunc(char *string) {
    char buffer[1024];
    strcpy(buffer, string);   // ⚠️ strcpy ne vérifie PAS la taille
    return 1;
}

int main(int argc, char *argv[]) {
    bowfunc(argv[1]);         // l’utilisateur contrôle argv[1]
    printf("Done.\n");
    return 1;
}
```

⚠️ `strcpy` est une fonction dangereuse car elle copie sans limite → vulnérabilité.

***

### <mark style="color:red;">5️⃣ Compilation avec protections désactivées</mark>

```bash
# Installer support 32 bits
sudo apt install gcc-multilib

# Compiler sans protections
gcc bow.c -o bow32 -fno-stack-protector -z execstack -m32

# Vérifier le format du binaire
file bow32 | tr "," "\n"
```

```
ELF 32-bit LSB shared object
Intel 80386
...
```

***

### <mark style="color:red;">6️⃣ Désactiver l’ASLR (temporairement)</mark>

```bash
sudo su
echo 0 > /proc/sys/kernel/randomize_va_space
cat /proc/sys/kernel/randomize_va_space
# 0 = désactivé
```

***

### <mark style="color:red;">7️⃣ Fonctions C vulnérables (à éviter !)</mark>

* `strcpy`
* `gets`
* `sprintf`
* `scanf`
* `strcat`

***

### <mark style="color:red;">8️⃣ Analyse avec GDB</mark>

Lancement :

```bash
gdb -q bow32
```

<mark style="color:green;">**Désassemblage (AT\&T syntaxe par défaut) :**</mark>

{% code fullWidth="true" %}
```asm
Dump of assembler code for function main:
   0x00000582 <+0>:  lea    0x4(%esp),%ecx
   0x00000586 <+4>:  and    $0xfffffff0,%esp
   0x00000589 <+7>:  pushl  -0x4(%ecx)
   0x0000058c <+10>: push   %ebp
   0x0000058d <+11>: mov    %esp,%ebp
   0x0000058f <+13>: push   %ebx
   0x00000590 <+14>: push   %ecx
   0x00000591 <+15>: call   0x450 <__x86.get_pc_thunk.bx>
   ...
   0x000005aa <+40>: call   0x54d <bowfunc>   ; 🔑 ICI bowfunc est appelé
   ...
   
   
   
(gdb) set disassembly-flavor intel
(gdb) disassemble main
```
{% endcode %}

***

### <mark style="color:red;">9️⃣ Passer en syntaxe Intel (plus lisible)</mark>

```gdb
set disassembly-flavor intel
disassemble main
```

<mark style="color:green;">**Exemple (Intel syntaxe) :**</mark>

{% hint style="info" %}
esp -> \[adresse de retour] <- Poussée par l'instruction 'call main'\
esp+0x4 -> \[argc] <- Premier argument (nombre d'arguments)\
esp+0x8 -> \[argv] <- Deuxième argument (tableau des arguments)\
esp+0xc -> \[envp] <- Troisième argument (variables d'environnement)
{% endhint %}

{% code fullWidth="true" %}
```nasm
student@nix-bow:~$ gdb ./bow32 -q

Reading symbols from bow...(no debugging symbols found)...done.
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>: 	lea    ecx,[esp+0x4]
   0x00000586 <+4>: 	and    esp,0xfffffff0
   
   
   0x00000589 <+7>: 	push   DWORD PTR [ecx-0x4]
   
   0x0000058c <+10>:	push   ebp
   0x0000058d <+11>:	mov    ebp,esp
   0x0000058f <+13>:	push   ebx
   0x00000590 <+14>:	push   ecx
   
   
   0x00000591 <+15>:	call   0x450 <__x86.get_pc_thunk.bx>
   0x00000596 <+20>:	add    ebx,0x1a3e
   
   
   0x0000059c <+26>:	mov    eax,ecx
   0x0000059e <+28>:	mov    eax,DWORD PTR [eax+0x4]
   0x000005a1 <+31>:	add    eax,0x4
   0x000005a4 <+34>:	mov    eax,DWORD PTR [eax]
   
   
   0x000005a6 <+36>:	sub    esp,0xc
   0x000005a9 <+39>:	push   eax
   0x000005aa <+40>:	call   0x54d <bowfunc>
   0x000005af <+45>:	add    esp,0x10
   
   
   0x000005b2 <+48>:	sub    esp,0xc
   0x000005b5 <+51>:	lea    eax,[ebx-0x1974]
   0x000005bb <+57>:	push   eax
   0x000005bc <+58>:	call   0x3e0 <puts@plt>
   0x000005c1 <+63>:	add    esp,0x10
   
   
   0x000005c4 <+66>:	mov    eax,0x1
   0x000005c9 <+71>:	lea    esp,[ebp-0x8]
   0x000005cc <+74>:	pop    ecx
   0x000005cd <+75>:	pop    ebx
   0x000005ce <+76>:	pop    ebp
   0x000005cf <+77>:	lea    esp,[ecx-0x4]
   0x000005d2 <+80>:	ret    
End of assembler dump.
```
{% endcode %}

<mark style="color:green;">**Pour le mettre par défaut :**</mark>

```bash
echo 'set disassembly-flavor intel' > ~/.gdbinit
```

{% code fullWidth="true" %}
```nasm
Dump of assembler code for function bowfunc:
   0x08049176 <+0>:	push   ebp
   0x08049177 <+1>:	mov    ebp,esp
   
   0x08049179 <+3>:	sub    esp,0x408
   0x0804917f <+9>:	sub    esp,0x8
   
   0x08049182 <+12>:	push   DWORD PTR [ebp+0x8]
   0x08049185 <+15>:	lea    eax,[ebp-0x408]
   0x0804918b <+21>:	push   eax
   0x0804918c <+22>:	call   0x8049040 <strcpy@plt>
   
   
   0x08049191 <+27>:	add    esp,0x10
   0x08049194 <+30>:	mov    eax,0x1
   0x08049199 <+35>:	leave
   0x0804919a <+36>:	ret

```
{% endcode %}

***

### <mark style="color:$danger;">🔟 Résumé des points clés</mark>

* **.text** → code exécutable
* **.data** → variables globales initialisées
* **.bss** → variables globales non initialisées (réservées via `resb`, etc.)
* **Heap** → mémoire dynamique (malloc/free)
* **Stack** → pile (variables locales, adresses de retour)
* Buffer overflow = écrasement de la pile → modification de l’exécution.
* Protections DEP/ASLR compliquent l’exploitation → d’où besoin de techniques comme ROP.
* GDB est l’outil principal pour observer et exploiter.

***
