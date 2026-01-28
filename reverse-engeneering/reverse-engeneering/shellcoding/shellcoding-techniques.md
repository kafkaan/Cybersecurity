# Shellcoding Techniques

***

### <mark style="color:blue;">✅ Exigences du Shellcoding</mark>

{% hint style="info" %}
Comme nous l'avons brièvement mentionné dans la section précédente, tous les binaires ne produisent pas des shellcodes valides pouvant être directement chargés en mémoire et exécutés.\
C’est parce qu’un shellcode doit répondre à certaines **exigences spécifiques**, sinon il ne sera pas désassemblé correctement à l’exécution.
{% endhint %}

{% code fullWidth="true" %}
```bash
$ pwn disasm '48be0020400000000000bf01000000ba12000000b8010000000f05b83c000000bf000000000f05' -c 'amd64'
```
{% endcode %}

Résultat :

{% code fullWidth="true" %}
```asm
0:  48 be 00 20 40 00 00     movabs rsi,  0x402000
7:  00 00 00
a:  bf 01 00 00 00           mov    edi,  0x1
f:  ba 12 00 00 00           mov    edx,  0x12
14: b8 01 00 00 00           mov    eax,  0x1
19: 0f 05                    syscall
1b: b8 3c 00 00 00           mov    eax,  0x3c
20: bf 00 00 00 00           mov    edi,  0x0
25: 0f 05                    syscall
```
{% endcode %}

On voit que les instructions sont relativement similaires au code Hello World précédent, mais **pas identiques**.

* On remarque une **ligne vide** qui pourrait casser le code.
* La chaîne Hello World n’apparaît nulle part.
* Et on voit aussi **beaucoup de 00 rouges**, on va y revenir.

C’est ce qui se passe quand le code assembleur **ne respecte pas les exigences du shellcoding**.

***

### <mark style="color:blue;">📋 Les 3 Exigences du Shellcoding :</mark>

1. ❌ **Ne pas contenir de variables**
2. ❌ **Ne pas référencer d’adresses mémoire directes**
3. ❌ **Ne pas contenir de bytes NULL (`0x00`)**

***

### <mark style="color:blue;">1️⃣ Supprimer les</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**variables**</mark>

Un shellcode doit être **exécutable directement** en mémoire. Il ne peut **pas charger des données** depuis d’autres segments mémoire (`.data`, `.bss`).\
Pourquoi ?

* `.text` (code) → **exécutable**, mais **non modifiable**
* `.data` → **modifiable**, mais **non exécutable**

Donc tout le shellcode doit être **dans la section `.text`**.

> 🔐 Note : certaines anciennes techniques comme `jmp-call-pop` ne fonctionnent plus avec les protections modernes mémoire.

***

#### <mark style="color:green;">✅ Solutions pour ne pas utiliser de variables :</mark>

* **Déplacer les chaînes immédiates** dans des **registres**
* **Pusher** des chaînes sur la **pile (stack)**

Exemple :

```asm
mov rsi, 'Academy!'         ; Pas assez si > 8 caractères
```

Donc mieux : **pusher la chaîne en morceaux** sur la stack, puis pointer `rsi` sur `rsp` :

```asm
push 'y!'
push 'B Academ'
push 'Hello HT'
mov rsi, rsp
```

Mais les `push` immédiats sont limités à 4 bytes (`dword`) → donc on utilise :

```asm
mov rbx, 'y!'
push rbx
mov rbx, 'B Academ'
push rbx
mov rbx, 'Hello HT'
push rbx
mov rsi, rsp
```

> **📝 Note : on n’a pas besoin d’un byte `\x00` pour terminer la chaîne, car `write` prend une taille explicite.**

***

#### <mark style="color:blue;">🔧 Compilation et test :</mark>

```bash
./assembler.sh helloworld.s
```

Résultat :

```
Hello HTB Academy!
```

***

#### <mark style="color:green;">🐛 Debug avec GDB :</mark>

```bash
gdb -q ./helloworld
```

Affichage :

```
$rax   : 0x1               
$rbx   : 0x5448206f6c6c6548 ("Hello HT"?)
$rdx   : 0x12              
$rsp   : ... → "Hello HTB Academy!"
$rsi   : ... → "Hello HTB Academy!"
```

***

### <mark style="color:blue;">2️⃣ Supprimer les</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**adresses absolues**</mark>

Maintenant, on n'utilise **aucune adresse fixe**.\
Mais attention : les `call` vers des **adresses fixes** cassent les shellcodes.

#### <mark style="color:green;">✅ Bonnes pratiques :</mark>

* Toujours faire des `call label` (NASM les transforme en `RIP-relative`)
* **Jamais de `call 0xdeadbeef`**
* Pour les `mov`, préférer `rsp` + `push`

***

### <mark style="color:blue;">3️⃣ Supprimer les</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**NULL bytes (0x00)**</mark>

Un shellcode avec `0x00` est souvent **coupé** lors d’un overflow → dangereux.

Exemple :

```bash
pwn asm 'mov rax, 1' -c 'amd64'
# Résultat : 48c7c001000000 ← contient des 00
```

Donc : on préfère :

```asm
xor rax, rax
mov al, 1
```

Test :

```bash
$ pwn asm 'xor rax, rax' -c 'amd64'
4831c0

$ pwn asm 'mov al, 1' -c 'amd64'
b001
```

→ ✅ Pas de NULL bytes\
→ ✅ Plus court = mieux pour un shellcode

***

#### <mark style="color:green;">🧼 Exemple avec</mark> <mark style="color:green;"></mark><mark style="color:green;">`rbx`</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

```asm
xor rbx, rbx
mov bx, 'y!'
```

Même technique appliquée au reste :

```asm
xor rax, rax
mov al, 1
xor rdi, rdi
mov dil, 1
xor rdx, rdx
mov dl, 18
syscall

xor rax, rax
add al, 60
xor dil, dil
syscall
```

***

### <mark style="color:blue;">🔁 Code final sans variable, sans adresse fixe, sans NULL</mark>

ssize\_t write(int fd, const void \*buf, size\_t count);

| Argument | Registre utilisé (x86\_64) |
| -------- | -------------------------- |
| `fd`     | `rdi`                      |
| `buf`    | `rsi`                      |
| `count`  | `rdx`                      |

```asm
global _start

section .text
_start:
    xor rbx, rbx
    mov bx, 'y!'
    push rbx
    mov rbx, 'B Academ'
    push rbx
    mov rbx, 'Hello HT'
    push rbx
    mov rsi, rsp
    xor rax, rax
    mov al, 1
    xor rdi, rdi
    mov dil, 1
    xor rdx, rdx
    mov dl, 18
    syscall

    xor rax, rax
    add al, 60
    xor dil, dil
    syscall
```

***

### <mark style="color:blue;">🛠️ Exécution</mark>

```bash
./assembler.sh helloworld.s
```

Résultat :

```
Hello HTB Academy!
```

***

### <mark style="color:blue;">💾 Extraction du shellcode</mark>

```bash
python3 shellcoder.py helloworld
```

Résultat :

```
4831db66bb79215348bb422041636164656d5348bb48656c6c6f204854534889e64831c0b0014831ff40b7014831d2b2120f054831c0043c4030ff0f05
```

***

#### <mark style="color:green;">🔍 Vérifier s’il y a des NULLs dans le shellcode</mark>

Ajoute à la fin de `shellcoder.py` :

{% code fullWidth="true" %}
```python
print("%d bytes - Found NULL byte" % len(shellcode)) if [i for i in shellcode if i == 0] else print("%d bytes - No NULL bytes" % len(shellcode))
```
{% endcode %}

```bash
python3 shellcoder.py helloworld
```

```
4831db66bb79215348bb422041636164656d5348bb48656c6c6f204854534889e64831c0b0014831ff40b7014831d2b2120f054831c0043c4030ff0f05  
61 bytes - No NULL bytes
```

✅ Aucun NULL byte détecté.

***

### <mark style="color:blue;">🚀 Dernière étape : lancer le shellcode</mark>

```bash
python3 loader.py '4831db66bb79215348bb422041636164656d5348bb48656c6c6f204854534889e64831c0b0014831ff40b7014831d2b2120f054831c0043c4030ff0f05'
```

Résultat :

```
Hello HTB Academy!
```

***
