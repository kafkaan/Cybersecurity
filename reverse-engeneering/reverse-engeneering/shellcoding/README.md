# Shellcoding

***

### <mark style="color:blue;">Qu’est-ce qu’un Shellcode ?</mark>

Un **shellcode** est <mark style="color:orange;">**la représentation hexadécimale du code machine exécutable d’un binaire**</mark><mark style="color:orange;">.</mark>

{% code fullWidth="true" %}
```nasm
global _start

section .data
    message db "Hello HTB Academy!"

section .text
_start:
    mov rsi, message
    mov rdi, 1
    mov rdx, 18
    mov rax, 1
    syscall

    mov rax, 60
    mov rdi, 0
    syscall
```
{% endcode %}

Cela nous donne

```shell
48be0020400000000000bf01000000ba12000000b8010000000f05b83c000000bf000000000f05
```

Ce shellcode représente correctement les instructions machines, et si on le charge dans la mémoire du processeur, il devrait être compris et exécuté correctement.

***

### <mark style="color:blue;">💥 Utilisation en Pentesting</mark>

:syringe: Pouvoir **injecter un shellcode directement dans la mémoire du processeur** et le faire exécuter joue un rôle essentiel dans l’**exploitation binaire**.

* Par exemple, avec un **buffer overflow**, on peut injecter un shellcode de **reverse shell**, le faire exécuter, et recevoir un shell distant.

:unlock: Les systèmes modernes x86\_64 peuvent avoir des **protections contre le chargement de shellcode** en mémoire.

* C’est pourquoi l’exploitation binaire en x86\_64 repose souvent sur le **ROP (Return Oriented Programming)**, qui nécessite aussi une **bonne compréhension du langage assembleur et de l’architecture machine**.

{% hint style="info" %}
<mark style="color:green;">**📌 C’est quoi concrètement le ROP ?**</mark>

Le ROP consiste à **réutiliser du code existant** déjà présent dans le binaire ou les librairies chargées (comme libc) pour **exécuter une chaîne d'instructions malicieuses**, **sans injecter de nouveau code**.

***

<mark style="color:green;">**🧱 Comment ça marche ?**</mark>

1. Le programme a une **vulnérabilité de type "buffer overflow"** (ex. : dépassement de tampon sur la pile).
2. Au lieu d’écrire un shellcode dans la pile (ce qui est souvent bloqué), l’attaquant :
   * Contrôle le **retour de la fonction** (adresse `ret`).
   * Utilise cela pour chaîner des petits morceaux de code existants dans le binaire, appelés **gadgets**.
3. Un **gadget** est un petit bout d’instructions qui se termine par `ret` (ou parfois `jmp`, `call`, etc.).
   * Exemple : `pop rdi; ret` ou `mov rax, rdi; ret`
4. En contrôlant la pile, on peut faire exécuter **plusieurs gadgets à la suite**, et ainsi construire une sorte de **programme à base de ret**, d'où le nom **Return-Oriented Programming**.

***

<mark style="color:green;">**🛠 Exemple très simple**</mark>

Imaginons qu'on a ces gadgets disponibles :

* `pop rdi; ret` (pour placer une valeur dans le registre `rdi`)
* `pop rsi; ret` (placer une valeur dans `rsi`)
* `call system` ou `jmp [rax]` (appeler une fonction système)

On peut faire une chaîne (ROP chain) comme :

```
[adresse de pop rdi; ret]
[adresse de la chaîne "/bin/sh"]
[adresse de system]
```
{% endhint %}

D'autres techniques d'attaque consistent à **infecter des exécutables existants** (comme des ELF ou .exe) ou des bibliothèques (.so ou .dll) avec un shellcode, qui sera chargé et exécuté lorsqu’on lancera ces fichiers.

:minidisc: Un **autre avantage des shellcodes en pentesting** est qu’on peut exécuter directement du code en mémoire **sans rien écrire sur le disque**, ce qui réduit la visibilité et les traces laissées sur le système cible.

***

### <mark style="color:blue;">🧬 De l’assembleur au code machine</mark>

Chaque **instruction x86 et chaque registre** a son propre code binaire machine (représenté en hex), transmis directement au processeur pour lui dire quoi exécuter.

Exemples :

* `push rax` → `50`
* `push rbx` → `53`

Quand on assemble notre code avec `nasm`, il **convertit les instructions en code machine**.

Nous allons utiliser **pwntools** pour assembler/désassembler du code, un outil essentiel en exploitation binaire.

```bash
sudo pip3 install pwntools
```

<mark style="color:green;">**Assembler une instruction :**</mark>

```bash
pwn asm 'push rax' -c 'amd64'
```

```bash
0:  50   push eax
```

<mark style="color:green;">**On peut aussi désassembler une instruction hexadécimale :**</mark>

```bash
pwn disasm '50' -c 'amd64'
```

```bash
0:  50   push eax
```

***

### <mark style="color:blue;">🧪 Extraire un Shellcode</mark>

Un **shellcode représente uniquement la section exécutable `.text`** d’un binaire.

Utilisez `pwntools` pour lire un binaire ELF et extraire sa section `.text` :

```bash
python3
```

```python
from pwn import *
file = ELF('helloworld')
file.section(".text").hex()
```

```shell
48be0020400000000000bf01000000ba12000000b8010000000f05b83c000000bf000000000f05
```

#### <mark style="color:green;">Script Python pour automatiser :</mark>

```python
#!/usr/bin/python3

import sys
from pwn import *

context(os="linux", arch="amd64", log_level="error")

file = ELF(sys.argv[1])
shellcode = file.section(".text")
print(shellcode.hex())
```

```bash
python3 shellcoder.py helloworld
```

***

#### <mark style="color:green;">🪛 Méthode alternative avec</mark> <mark style="color:green;"></mark><mark style="color:green;">`objdump`</mark>

```bash
#!/bin/bash

for i in $(objdump -d $1 |grep "^ " |cut -f2); do echo -n $i; done; echo;
```

Exécution :

```bash
./shellcoder.sh helloworld
```

{% hint style="warning" %}
***

**1. `objdump -d $1`**

* `objdump` est un outil pour **désassembler** un binaire.
* `-d` signifie : désassembler le binaire donné en argument (`$1` = premier argument, ex : `helloworld`).

👉 Ça produit un désassemblage du type :

```
08048400 <main>:
 8048400: b8 04 00 00 00        mov    eax,0x4
 8048405: bb 01 00 00 00        mov    ebx,0x1
```

***

**2. `grep "^ "`**

* Cela filtre uniquement les lignes qui **commencent par un espace**, c’est-à-dire les **lignes contenant du code assembleur** (et pas les labels comme `<main>`).

***

**3. `cut -f2`**

* `cut` permet d’extraire **la 2ᵉ colonne**.
* Dans les lignes désassemblées, la 2ᵉ colonne contient **les opcodes hexadécimaux**, par exemple :

```
8048400: b8 04 00 00 00
```

La 2ᵉ colonne ici serait : `b8`.

⚠️ Mais en réalité, `cut -f2` avec tabulation (`-f2`) ne marche que si les colonnes sont bien séparées par **des tabulations**, ce qui n’est pas toujours le cas. Cette commande fonctionne selon le format de sortie de `objdump`.

***

**4. Boucle `for i in ... ; do echo -n $i; done`**

* Elle **parcourt chaque octet extrait**.
* `echo -n $i` : affiche chaque octet **à la suite**, sans retour à la ligne.

***

**5. `echo;`**

* Imprime un saut de ligne à la fin, pour ne pas avoir la sortie sur la même ligne que le terminal.

***
{% endhint %}

***

### <mark style="color:blue;">🚀 Lancer un Shellcode</mark>

Prenons un shellcode qui respecte toutes les contraintes :

```shell
4831db66bb79215348bb422041636164656d5348bb48656c6c6f204854534889e64831c0b0014831ff40b7014831d2b2120f054831c0043c4030ff0f05
```

Lancer via pwntools :

```python
python3
```

{% code fullWidth="true" %}
```python
from pwn import *
context(os="linux", arch="amd64", log_level="error")
run_shellcode(unhex('4831db66bb79...c4030ff0f05')).interactive()
```
{% endcode %}

```
Hello HTB Academy!
```

Tester un shellcode **non conforme** :

{% code fullWidth="true" %}
```python
run_shellcode(unhex('b801000000bf0100000048..0000000f05b83c000000bf000000000f05')).interactive()
```
{% endcode %}

***

#### <mark style="color:green;">Script Python</mark> <mark style="color:green;"></mark><mark style="color:green;">`loader.py`</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

{% code fullWidth="true" %}
```python
#!/usr/bin/python3

import sys
from pwn import *

context(os="linux", arch="amd64", log_level="error")

run_shellcode(unhex(sys.argv[1])).interactive()
```
{% endcode %}

Utilisation :

```bash
python3 loader.py '4831db66bb79215348bb422041636164656d5348bb48656c6c6f204854534889e64831c0b0014831ff40b7014831d2b2120f054831c0043c4030ff0f05'
```

***

### <mark style="color:blue;">🐞 Déboguer un Shellcode</mark>

Vous pouvez attacher `gdb` au processus exécuté par `loader.py`, **ou** créer un exécutable ELF avec le shellcode.

Créer un binaire ELF :

```python
ELF.from_bytes(unhex('4831db66bb79215348bb422041636164656d5348bb48656c6c6f204854534889e64831c0b0014831ff40b7014831d2b2120f054831c0043c4030ff0f05')).save('helloworld')
```

***

#### <mark style="color:green;">Script</mark> <mark style="color:green;"></mark><mark style="color:green;">`assembler.py`</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

```python
#!/usr/bin/python3

import sys, os, stat
from pwn import *

context(os="linux", arch="amd64", log_level="error")

ELF.from_bytes(unhex(sys.argv[1])).save(sys.argv[2])
os.chmod(sys.argv[2], stat.S_IEXEC)
```

Utilisation :

```bash
python3 assembler.py '4831db66bb79215348bb422041636164656d5348bb48656c6c6f204854534889e64831c0b0014831ff40b7014831d2b2120f054831c0043c4030ff0f05' helloworld
./helloworld
```

Debug avec GDB :

```bash
gdb -q helloworld
gef➤  b *0x401000
gef➤  r
```

***

### <mark style="color:blue;">⚠️ Autre méthode : Compilation avec GCC</mark>

```c
#include <stdio.h>

int main()
{
    int (*ret)() = (int (*)()) "\x48\x31\xdb\x66\xbb...SNIP...\x0f\x05";
    ret();l
}
```

Compiler :

```bash
gcc helloworld.c -o helloworld
```

Si erreur, compiler avec options :

{% code fullWidth="true" %}
```bash
gcc helloworld.c -o helloworld -fno-stack-protector -z execstack -Wl,--omagic -g --static
```
{% endcode %}

Exécution :

```bash
./helloworld
```

***
