# Assembling & Disassembling

***

Toute la structure de fichier que nous avons apprise dans la section précédente est **basée sur la structure de fichier `nasm`**.\
Lorsque nous assemblons notre code avec `nasm`, il **comprend les différentes parties du fichier** et les **assemble correctement** pour qu’elles puissent être exécutées **durant l’exécution** du programme.

Après avoir assemblé notre code avec `nasm`, nous pouvons **le lier** en utilisant `ld` pour utiliser les différentes fonctionnalités et bibliothèques du système d’exploitation.

***

### <mark style="color:blue;">🧱 Assemblage</mark>

Tout d’abord, nous allons copier le code ci-dessous dans un fichier appelé **`helloWorld.s`**.

> 📝 Remarque : les fichiers assembleur utilisent généralement l’extension `.s` ou `.asm`.\
> Dans ce module, nous allons utiliser `.s`.

> 🧑‍💻 On n’est pas obligé de mettre des tabulations pour séparer les parties d’un fichier assembleur,\
> c’était juste pour l’exemple. Voici le code à placer dans `helloWorld.s` :

***

#### <mark style="color:green;">📄 Code (nasm)</mark>

```nasm
global _start

section .data
    message db "Hello HTB Academy!"
    length equ $-message

section .text
_start:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    mov rdx, length
    syscall

    mov rax, 60
    mov rdi, 0
    syscall
```

***

Maintenant, **assemblons le fichier avec `nasm`**, via la commande suivante :

```bash
nasm -f elf64 helloWorld.s
```

> 📝 Remarque : le flag `-f elf64` signifie qu’on veut assembler un **code assembleur 64 bits**.\
> Si on voulait assembler du **32 bits**, on utiliserait `-f elf`.

***

Cela va produire un fichier **`helloWorld.o`** (fichier objet), qui est du code machine, avec les détails de toutes les variables et sections. Mais ce fichier **n’est pas encore exécutable**.

***

### <mark style="color:blue;">🔗 Linkage (Édition de liens)</mark>

L’étape finale est de **lier** le fichier avec **`ld`**.

{% hint style="info" %}
Le fichier **`helloWorld.o`**, même s’il est assemblé, **ne peut pas encore être exécuté c**ar plusieurs **références et labels** utilisés par `nasm` doivent être **résolus en adresses réelles**,  et le fichier doit être **lié à certaines bibliothèques du système**.
{% endhint %}

***

C’est pour cela qu’un binaire Linux est appelé **ELF** (Executable and Linkable Format).

Pour le **lier** avec `ld` :

```bash
ld -o helloWorld helloWorld.o
```

> 📝 Remarque : pour un binaire 32 bits, il faudrait ajouter `-m elf_i386`.

***

Une fois le fichier lié, nous avons un exécutable final :

```bash
./helloWorld
Hello HTB Academy!
```

✅ On a assemblé et lié **notre premier fichier assembleur avec succès**.

***

### <mark style="color:blue;">🤖 Automatiser avec un script bash</mark>

Comme on va souvent assembler, lier et exécuter, on peut créer un **petit script bash** :

```bash
#!/bin/bash

fileName="${1%%.*}" # retirer l'extension .s

nasm -f elf64 ${fileName}.s
ld ${fileName}.o -o ${fileName}
[ "$2" == "-g" ] && gdb -q ${fileName} || ./${fileName}
```

***

Enregistrez ce script dans **`assembler.sh`**, donnez-lui les droits d’exécution :

```bash
chmod +x assembler.sh
```

Puis utilisez-le :

```bash
./assembler.sh helloWorld.s
Hello HTB Academy!
```

***

### <mark style="color:blue;">🔎 Désassemblage</mark>

Avant d’aller plus loin, regardons maintenant **comment désassembler un fichier**\
pour mieux comprendre le processus qu’on vient de faire.

Nous allons utiliser **`objdump`**, qui affiche le code machine et **interprète les instructions assembleur**\
à partir d’un fichier binaire.

***

Pour désassembler un binaire, utilisez le flag `-d`.

> 📝 On ajoute aussi `-M intel` pour afficher le code avec la **syntaxe Intel**, comme celle utilisée ici.

***

#### <mark style="color:green;">📤 Désassembler notre exécutable :</mark>

```bash
objdump -M intel -d helloWorld
```

***

#### <mark style="color:green;">🔍 Exemple de sortie :</mark>

```
helloWorld:     file format elf64-x86-64

Disassembly of section .text:

0000000000401000 <_start>:
  401000:	b8 01 00 00 00       	mov    eax,0x1
  401005:	bf 01 00 00 00       	mov    edi,0x1
  40100a:	48 be 00 20 40 00 00 	movabs rsi,0x402000
  401011:	00 00 00
  401014:	ba 12 00 00 00       	mov    edx,0x12
  401019:	0f 05                	syscall
  40101b:	b8 3c 00 00 00       	mov    eax,0x3c
  401020:	bf 00 00 00 00       	mov    edi,0x0
  401025:	0f 05                	syscall
```

On voit que notre code assembleur **a bien été traduit**,\
avec quelques changements :

* `message` → remplacé par son **adresse réelle `0x402000`**
* `length` → remplacé par la **valeur 0x12 (18 en décimal)**
* Certains registres 64 bits ont été optimisés en 32 bits (`mov rax` → `mov eax`)

***

### <mark style="color:blue;">🧼 Afficher</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**seulement les instructions**</mark> <mark style="color:blue;"></mark><mark style="color:blue;">(sans hex ni adresses)</mark>

```bash
objdump -M intel --no-show-raw-insn --no-addresses -d helloWorld
```

🔁 Cela affichera uniquement :

```asm
<_start>:
    mov    eax,0x1
    mov    edi,0x1
    movabs rsi,0x402000
    mov    edx,0x12
    syscall 
    mov    eax,0x3c
    mov    edi,0x0
    syscall
```

> 📝 `movabs` est équivalent à `mov` mais utilisé pour des **valeurs 64 bits absolues**.

***

### <mark style="color:blue;">📥 Voir les</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**chaînes de caractères dans .data**</mark>

Pour afficher le contenu de la section `.data` (où est stockée la variable `message`) :

```bash
objdump -sj .data helloWorld
```

🔎 Exemple de sortie :

```
helloWorld:     file format elf64-x86-64

Contents of section .data:
 402000 48656c6c 6f204854 42204163 6164656d  Hello HTB Academ
 402010 7921                                 y!
```

On voit bien la chaîne `"Hello HTB Academy!"` stockée à l’adresse `0x402000`.

***

<mark style="color:green;">✅</mark> <mark style="color:green;"></mark><mark style="color:green;">**Conclusion**</mark>

* On a assemblé (`nasm`), lié (`ld`), exécuté (`./helloWorld`)
* On a désassemblé (`objdump`)
* On a compris la conversion entre assembleur, code machine, et sections mémoire (`.text`, `.data`)
* On est prêt pour le **debugging et l’exploitation binaire**

***

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Commande</strong></td><td><strong>Description</strong></td><td><strong>Exemple</strong></td></tr><tr><td><code>nasm -f elf64 file.s</code></td><td>Assembler un fichier source 64 bits</td><td><code>nasm -f elf64 hello.s -o hello.o</code></td></tr><tr><td><code>nasm -f elf file.s</code></td><td>Assembler un fichier source 32 bits</td><td><code>nasm -f elf hello32.s -o hello32.o</code></td></tr><tr><td><code>nasm -g -F dwarf -f elf64 file.s</code></td><td>Assembler avec symboles de debug</td><td><code>nasm -g -F dwarf -f elf64 prog.s -o prog.o</code></td></tr><tr><td><code>ld -o prog prog.o</code></td><td>Lier un fichier objet en exécutable 64 bits</td><td><code>ld -o hello hello.o</code></td></tr><tr><td><code>ld -m elf_i386 -o prog prog.o</code></td><td>Lier un exécutable 32 bits</td><td><code>ld -m elf_i386 -o hello32 hello32.o</code></td></tr><tr><td><code>./prog</code></td><td>Exécuter un binaire</td><td><code>./hello</code></td></tr><tr><td><code>strace ./prog</code></td><td>Tracer les appels système</td><td><code>strace ./hello</code></td></tr><tr><td><code>ltrace ./prog</code></td><td>Tracer les appels aux fonctions dynamiques (libc, etc.)</td><td><code>ltrace ./hello</code></td></tr><tr><td><code>objdump -M intel -d prog</code></td><td>Désassembler <code>.text</code> en syntaxe Intel</td><td><code>objdump -M intel -d hello</code></td></tr><tr><td><code>objdump -M intel -D prog</code></td><td>Désassembler <strong>tout</strong> le binaire</td><td><code>objdump -M intel -D hello</code></td></tr><tr><td><code>objdump -M intel --no-show-raw-insn --no-addresses -d prog</code></td><td>Désassemblage minimal (juste instructions)</td><td><code>objdump -M intel --no-show-raw-insn --no-addresses -d hello</code></td></tr><tr><td><code>objdump -h prog</code></td><td>Voir les sections ELF</td><td><code>objdump -h hello</code></td></tr><tr><td><code>objdump -s -j .data prog</code></td><td>Contenu brut de <code>.data</code></td><td><code>objdump -s -j .data hello</code></td></tr><tr><td><code>objdump -s -j .rodata prog</code></td><td>Contenu brut de <code>.rodata</code> (chaînes)</td><td><code>objdump -s -j .rodata hello</code></td></tr><tr><td><code>file prog</code></td><td>Vérifier type et architecture ELF</td><td><code>file hello</code></td></tr><tr><td><code>readelf -h prog</code></td><td>Voir l’en-tête ELF (archi, entrypoint)</td><td><code>readelf -h hello</code></td></tr><tr><td><code>readelf -S prog</code></td><td>Lister les sections</td><td><code>readelf -S hello</code></td></tr><tr><td><code>readelf -s prog</code></td><td>Table des symboles</td><td><code>readelf -s hello</code></td></tr><tr><td><code>readelf -r prog</code></td><td>Table des relocations</td><td><code>readelf -r hello</code></td></tr><tr><td><code>readelf -d prog</code></td><td>Section dynamique (libs utilisées)</td><td><code>readelf -d hello</code></td></tr><tr><td><code>strings prog</code></td><td>Extraire chaînes lisibles</td><td><code>strings hello</code></td></tr><tr><td><code>hexdump -C prog</code></td><td>Hexdump lisible</td><td><code>hexdump -C hello</code></td></tr><tr><td><code>xxd prog</code></td><td>Hexdump alternatif</td><td><code>xxd hello</code></td></tr><tr><td><code>nm prog</code></td><td>Lister les symboles (fonctions, variables)</td><td><code>nm hello</code></td></tr><tr><td><code>ldd prog</code></td><td>Voir les dépendances dynamiques</td><td><code>ldd hello</code></td></tr></tbody></table>
